"""Trusted provider verification and integration connection activation.

No API request can manufacture a verification result. A verifier must be
registered by application composition and must validate provider-side evidence.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from backend.app.persistence.integration_connections import IntegrationConnectionRepository
from backend.app.tools.integration_vault import IntegrationSecretVault


_FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class ProviderVerification:
    granted_scopes: tuple[str, ...]
    provider_subject_fingerprint: str
    expires_at: str | None = None


class ProviderConnectionVerifier(Protocol):
    verifier_id: str

    async def verify(
        self, *, user_id: str, integration_id: str, connection_id: str,
        credential_material: dict[str, Any], requested_scopes: tuple[str, ...],
    ) -> ProviderVerification:
        """Perform provider-specific remote verification and return bounded claims."""
        ...


class ProviderVerifierRegistry:
    def __init__(self) -> None:
        self._verifiers: dict[str, ProviderConnectionVerifier] = {}

    def register(self, integration_id: str, verifier: ProviderConnectionVerifier) -> None:
        if not isinstance(integration_id, str) or not integration_id:
            raise ValueError("Integration ID is invalid")
        verifier_id = getattr(verifier, "verifier_id", None)
        if not isinstance(verifier_id, str) or not verifier_id or len(verifier_id) > 100:
            raise ValueError("Provider verifier identity is invalid")
        if integration_id in self._verifiers:
            raise ValueError("A provider verifier is already registered")
        if not callable(getattr(verifier, "verify", None)):
            raise TypeError("Provider verifier must implement verify")
        self._verifiers[integration_id] = verifier

    def get(self, integration_id: str) -> ProviderConnectionVerifier | None:
        return self._verifiers.get(integration_id)


class IntegrationConnectionLifecycle:
    def __init__(
        self, *, connections: IntegrationConnectionRepository,
        vault: IntegrationSecretVault, verifiers: ProviderVerifierRegistry,
    ) -> None:
        self.connections = connections
        self.vault = vault
        self.verifiers = verifiers

    async def verify_and_activate(
        self, user_id: str, connection_id: str,
        credential_material: dict[str, Any],
    ) -> dict:
        if not self.vault.available:
            raise RuntimeError("Integration credential vault is unavailable")
        connection = self.connections.get(user_id, connection_id)
        if connection["status"] != "pending_verification":
            raise PermissionError("Only pending connections can be verified")
        integration_id = connection["integration_id"]
        verifier = self.verifiers.get(integration_id)
        if verifier is None:
            raise PermissionError("No trusted provider verifier is configured")
        requested = tuple(sorted(
            grant["scope"] for grant in connection["grants"]
            if grant["status"] == "pending"
        ))
        if not requested:
            raise PermissionError("Connection has no pending owner-approved scopes")
        if not isinstance(credential_material, dict) or not credential_material:
            raise ValueError("Provider credential material is invalid")

        verification = await verifier.verify(
            user_id=user_id, integration_id=integration_id,
            connection_id=connection_id,
            credential_material=credential_material,
            requested_scopes=requested,
        )
        if not isinstance(verification, ProviderVerification):
            raise PermissionError("Provider verifier returned an invalid result")
        if (
            not isinstance(verification.provider_subject_fingerprint, str)
            or not _FINGERPRINT.fullmatch(verification.provider_subject_fingerprint)
            or not isinstance(verification.granted_scopes, tuple)
            or any(not isinstance(scope, str) for scope in verification.granted_scopes)
            or len(set(verification.granted_scopes)) != len(verification.granted_scopes)
            or set(verification.granted_scopes) != set(requested)
        ):
            raise PermissionError("Provider identity or granted scopes do not match owner consent")
        if verification.expires_at is None:
            raise PermissionError("Provider credentials must have a finite expiry")
        if verification.expires_at is None:
            raise PermissionError("Rotated provider credentials must have a finite expiry")
        if verification.expires_at is not None:
            try:
                expiry = datetime.fromisoformat(verification.expires_at)
            except (TypeError, ValueError):
                raise PermissionError("Provider credential expiry is invalid") from None
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                raise PermissionError("Provider credential is expired or has invalid timezone")

        secret_ref = self.vault.store(
            user_id, connection_id, integration_id, credential_material
        )
        try:
            return self.connections.activate_verified(
                user_id, connection_id, secret_ref=secret_ref,
                verifier_id=verifier.verifier_id,
                provider_subject_fingerprint=verification.provider_subject_fingerprint,
                granted_scopes=verification.granted_scopes,
                expires_at=verification.expires_at,
            )
        except Exception:
            # Marking the pending record expired also invokes the DB trigger
            # that destroys any newly written ciphertext.
            self.connections.expire_pending(user_id, connection_id)
            raise


    async def rotate_verified(
        self, user_id: str, connection_id: str,
        credential_material: dict[str, Any],
    ) -> dict:
        """Verify a refreshed credential before replacing the encrypted payload."""
        if not self.vault.available:
            raise RuntimeError("Integration credential vault is unavailable")
        connection = self.connections.get(user_id, connection_id)
        if connection["status"] != "active":
            raise PermissionError("Only active connections can rotate credentials")
        integration_id = connection["integration_id"]
        verifier = self.verifiers.get(integration_id)
        if verifier is None:
            raise PermissionError("No trusted provider verifier is configured")
        scopes = tuple(sorted(
            grant["scope"] for grant in connection["grants"]
            if grant["status"] == "active" and grant["revoked_at"] is None
        ))
        if not scopes or not self.connections.has_active_grants(
            user_id, connection_id, integration_id, scopes
        ):
            raise PermissionError("Connection has no active owner-approved scopes")
        verification = await verifier.verify(
            user_id=user_id, integration_id=integration_id,
            connection_id=connection_id,
            credential_material=credential_material,
            requested_scopes=scopes,
        )
        previous_subject = self.connections.latest_provider_subject(
            user_id, connection_id
        )
        if (
            not isinstance(verification, ProviderVerification)
            or not isinstance(verification.provider_subject_fingerprint, str)
            or not _FINGERPRINT.fullmatch(verification.provider_subject_fingerprint)
            or verification.provider_subject_fingerprint != previous_subject
            or not isinstance(verification.granted_scopes, tuple)
            or any(not isinstance(scope, str) for scope in verification.granted_scopes)
            or tuple(sorted(verification.granted_scopes)) != scopes
        ):
            raise PermissionError("Rotated credential does not match the verified provider identity and scopes")
        if verification.expires_at is not None:
            try:
                expiry = datetime.fromisoformat(verification.expires_at)
            except (TypeError, ValueError):
                raise PermissionError("Provider credential expiry is invalid") from None
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                raise PermissionError("Rotated provider credential is expired")
        self.vault.rotate(
            user_id, connection_id, integration_id, credential_material
        )
        return self.connections.record_credential_rotation(
            user_id, connection_id,
            verifier_id=verifier.verifier_id,
            provider_subject_fingerprint=verification.provider_subject_fingerprint,
            expires_at=verification.expires_at,
        )
