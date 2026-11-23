import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import (
    verify_authentication_response,
)
from webauthn.helpers.parse_registration_credential_json import (
    parse_registration_credential_json,
)
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.parse_client_data_json import parse_client_data_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    ClientDataType,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from backend.app.persistence.tool_requests import _request_digest


class WebAuthnService:
    """Verify passkey assertions before committing tool authorization."""

    _TRANSPORTS = {
        "usb": AuthenticatorTransport.USB,
        "nfc": AuthenticatorTransport.NFC,
        "ble": AuthenticatorTransport.BLE,
        "internal": AuthenticatorTransport.INTERNAL,
        "hybrid": AuthenticatorTransport.HYBRID,
        "cable": AuthenticatorTransport.CABLE,
        "smart-card": AuthenticatorTransport.SMART_CARD,
    }

    def __init__(self, *, repository, tool_requests, settings):
        self.repository = repository
        self.tool_requests = tool_requests
        self.settings = settings

    def _require_enabled(self):
        if (
            not self.settings.webauthn_enabled
            or not self.settings.webauthn_rp_id
            or not self.settings.webauthn_allowed_origins
        ):
            raise PermissionError("WebAuthn is not enabled or configured")

    @staticmethod
    def _parse_expiry(value, field_name):
        if not isinstance(value, str) or not value.strip():
            raise PermissionError(f"{field_name} is missing")

        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise PermissionError(f"{field_name} is invalid") from exc

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise PermissionError(f"{field_name} must include a timezone")

        return parsed

    @staticmethod
    def _decode_stored_credential_id(value):
        if not isinstance(value, str) or not value:
            raise PermissionError("Stored passkey credential ID is invalid")

        try:
            decoded = base64url_to_bytes(value)
        except Exception as exc:
            raise PermissionError(
                "Stored passkey credential ID is invalid"
            ) from exc

        if not decoded or bytes_to_base64url(decoded) != value:
            raise PermissionError(
                "Stored passkey credential ID is not canonical Base64URL"
            )

        return decoded

    def _get_pending_request(self, user_id, request_id):
        request = self.tool_requests.get(user_id, request_id)

        if request["status"] != "pending" or request["consumed_at"] is not None:
            raise PermissionError("Tool request is not awaiting authorization")

        if request["authorization_policy"] != "passkey":
            raise PermissionError("Tool request does not require passkey authorization")

        expiry = self._parse_expiry(
            request["expires_at"],
            "Tool request expiry",
        )
        if expiry <= datetime.now(timezone.utc):
            raise PermissionError("Tool request has expired")

        fingerprint = request["contract_fingerprint"]
        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in fingerprint)
        ):
            raise PermissionError("Tool request contract fingerprint is invalid")

        try:
            digest = _request_digest(
                request["tool_id"],
                request["arguments"],
                fingerprint,
            )
        except (TypeError, ValueError) as exc:
            raise PermissionError("Tool request proposal is invalid") from exc

        return request, expiry, digest, fingerprint

    def create_tool_approval_options(
        self,
        *,
        user_id,
        request_id,
    ):
        """Create short-lived assertion options bound to one pending request."""
        self._require_enabled()

        request, request_expiry, digest, fingerprint = (
            self._get_pending_request(user_id, request_id)
        )

        credentials = self.repository.list_credentials(user_id)
        if not credentials:
            raise PermissionError("No active passkeys are registered")

        descriptors = []
        for credential in credentials:
            if credential["revoked_at"] is not None:
                continue

            raw_id = self._decode_stored_credential_id(
                credential["credential_id"]
            )

            try:
                transports = [
                    self._TRANSPORTS[item]
                    for item in credential["transports"]
                ]
            except (KeyError, TypeError) as exc:
                raise PermissionError(
                    "Stored passkey transport metadata is invalid"
                ) from exc

            descriptors.append(
                PublicKeyCredentialDescriptor(
                    id=raw_id,
                    transports=transports or None,
                )
            )

        if not descriptors:
            raise PermissionError("No active passkeys are available")

        now = datetime.now(timezone.utc)
        challenge_expiry = min(
            now + timedelta(
                seconds=self.settings.webauthn_challenge_ttl_seconds
            ),
            request_expiry,
        )

        if challenge_expiry <= now:
            raise PermissionError("Tool request has expired")

        raw_challenge = secrets.token_bytes(32)
        challenge_hash = hashlib.sha256(raw_challenge).hexdigest()

        options = generate_authentication_options(
            rp_id=self.settings.webauthn_rp_id,
            challenge=raw_challenge,
            allow_credentials=descriptors,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        challenge = self.repository.create_challenge(
            user_id=user_id,
            challenge_hash=challenge_hash,
            purpose="tool_approval",
            expires_at=challenge_expiry.isoformat(),
            request_id=request_id,
            proposal_digest=digest,
            contract_fingerprint=fingerprint,
        )

        return {
            "challenge_record_id": challenge["id"],
            "options": json.loads(options_to_json(options)),
        }

    def verify_tool_approval(
        self,
        *,
        user_id,
        request_id,
        challenge_record_id,
        credential_record_id,
        assertion,
    ):
        """Verify an assertion and atomically authorize its exact tool request."""
        self._require_enabled()

        request, _, digest, fingerprint = self._get_pending_request(
            user_id,
            request_id,
        )

        challenge = self.repository.get_challenge(
            user_id,
            challenge_record_id,
        )
        if challenge is None:
            raise LookupError("WebAuthn challenge not found")

        if (
            challenge["purpose"] != "tool_approval"
            or challenge["request_id"] != request_id
            or challenge["proposal_digest"] != digest
            or challenge["contract_fingerprint"] != fingerprint
            or challenge["consumed_at"] is not None
        ):
            raise PermissionError("WebAuthn challenge does not match this request")

        challenge_expiry = self._parse_expiry(
            challenge["expires_at"],
            "WebAuthn challenge expiry",
        )
        if challenge_expiry <= datetime.now(timezone.utc):
            raise PermissionError("WebAuthn challenge has expired")

        credential = self.repository.get_credential(
            user_id,
            credential_record_id,
        )
        if credential is None:
            raise LookupError("WebAuthn credential not found")

        if credential["revoked_at"] is not None:
            raise PermissionError("WebAuthn credential has been revoked")

        stored_credential_id = self._decode_stored_credential_id(
            credential["credential_id"]
        )

        # Parse and verify the untrusted browser assertion. No persistence
        # state is changed until cryptographic verification has succeeded.
        try:
            parsed_assertion = parse_authentication_credential_json(assertion)

            if (
                parsed_assertion.raw_id != stored_credential_id
                or parsed_assertion.id != credential["credential_id"]
            ):
                raise PermissionError(
                    "Assertion credential does not match the selected passkey"
                )

            client_data = parse_client_data_json(
                parsed_assertion.response.client_data_json
            )

            if client_data.type != ClientDataType.WEBAUTHN_GET:
                raise PermissionError("Assertion has an invalid client-data type")

            if client_data.cross_origin is True:
                raise PermissionError("Cross-origin WebAuthn assertions are rejected")

            supplied_challenge_hash = hashlib.sha256(
                client_data.challenge
            ).hexdigest()

            if not hmac.compare_digest(
                supplied_challenge_hash,
                challenge["challenge_hash"],
            ):
                raise PermissionError("WebAuthn challenge does not match")

            verified = verify_authentication_response(
                credential=parsed_assertion,
                expected_challenge=client_data.challenge,
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=list(self.settings.webauthn_allowed_origins),
                credential_public_key=credential["public_key"],
                credential_current_sign_count=credential["sign_count"],
                require_user_verification=True,
            )

            if verified.credential_id != stored_credential_id:
                raise PermissionError("Verified credential ID does not match")

            if not verified.user_verified:
                raise PermissionError("User verification is required")

        except PermissionError:
            raise
        except Exception as exc:
            # Do not expose parser, signature, or cryptographic internals.
            raise PermissionError("WebAuthn assertion verification failed") from exc

        # This transaction rechecks request, challenge, credential, expiry,
        # and signature-counter state before consuming the challenge.
        return self.repository.commit_verified_tool_authorization(
            user_id=user_id,
            request_id=request_id,
            challenge_record_id=challenge_record_id,
            credential_record_id=credential_record_id,
            verified_sign_count=verified.new_sign_count,
        )

    def create_authentication_options(self, *, user_id):
        """Create account-bound passkey sign-in options."""
        self._require_enabled()

        credentials = self.repository.list_credentials(user_id)
        descriptors = []

        for credential in credentials:
            if credential["revoked_at"] is not None:
                continue

            raw_id = self._decode_stored_credential_id(
                credential["credential_id"]
            )

            try:
                transports = [
                    self._TRANSPORTS[item]
                    for item in credential["transports"]
                ]
            except (KeyError, TypeError) as exc:
                raise PermissionError(
                    "Stored passkey transport metadata is invalid"
                ) from exc

            descriptors.append(
                PublicKeyCredentialDescriptor(
                    id=raw_id,
                    transports=transports or None,
                )
            )

        if not descriptors:
            raise PermissionError("No active passkeys are registered")

        raw_challenge = secrets.token_bytes(32)
        challenge_hash = hashlib.sha256(raw_challenge).hexdigest()

        options = generate_authentication_options(
            rp_id=self.settings.webauthn_rp_id,
            challenge=raw_challenge,
            allow_credentials=descriptors,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        challenge_expiry = (
            datetime.now(timezone.utc)
            + timedelta(
                seconds=self.settings.webauthn_challenge_ttl_seconds
            )
        )

        challenge = self.repository.create_challenge(
            user_id=user_id,
            challenge_hash=challenge_hash,
            purpose="authentication",
            expires_at=challenge_expiry.isoformat(),
        )

        return {
            "challenge_record_id": challenge["id"],
            "options": json.loads(options_to_json(options)),
        }

    def verify_authentication(
        self,
        *,
        user_id,
        challenge_record_id,
        assertion,
    ):
        """Verify a passkey assertion and atomically consume its challenge."""
        self._require_enabled()

        challenge = self.repository.get_challenge(
            user_id,
            challenge_record_id,
        )

        if challenge is None:
            raise LookupError("WebAuthn challenge not found")

        if (
            challenge["purpose"] != "authentication"
            or challenge["consumed_at"] is not None
        ):
            raise PermissionError("Authentication challenge is unavailable")

        expiry = self._parse_expiry(
            challenge["expires_at"],
            "WebAuthn authentication challenge expiry",
        )
        if expiry <= datetime.now(timezone.utc):
            raise PermissionError("Authentication challenge has expired")

        # Resolve the credential from the assertion, scoped to this account.
        try:
            parsed_assertion = parse_authentication_credential_json(assertion)

            credential_id = parsed_assertion.id
            credential = self.repository.get_credential_by_credential_id(
                user_id,
                credential_id,
            )

            if credential is None:
                raise LookupError("WebAuthn credential not found")

            if credential["revoked_at"] is not None:
                raise PermissionError("WebAuthn credential has been revoked")

            stored_credential_id = self._decode_stored_credential_id(
                credential["credential_id"]
            )

            if (
                parsed_assertion.raw_id != stored_credential_id
                or parsed_assertion.id != credential["credential_id"]
            ):
                raise PermissionError(
                    "Assertion credential ID does not match"
                )

            client_data = parse_client_data_json(
                parsed_assertion.response.client_data_json
            )

            if client_data.type != ClientDataType.WEBAUTHN_GET:
                raise PermissionError("Assertion has an invalid client-data type")

            if client_data.cross_origin is True:
                raise PermissionError(
                    "Cross-origin WebAuthn assertions are rejected"
                )

            supplied_challenge_hash = hashlib.sha256(
                client_data.challenge
            ).hexdigest()

            if not hmac.compare_digest(
                supplied_challenge_hash,
                challenge["challenge_hash"],
            ):
                raise PermissionError("WebAuthn challenge does not match")

            verified = verify_authentication_response(
                credential=parsed_assertion,
                expected_challenge=client_data.challenge,
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=list(self.settings.webauthn_allowed_origins),
                credential_public_key=credential["public_key"],
                credential_current_sign_count=credential["sign_count"],
                require_user_verification=True,
            )

            if verified.credential_id != stored_credential_id:
                raise PermissionError("Verified credential ID does not match")

            if not verified.user_verified:
                raise PermissionError("User verification is required")

        except (PermissionError, LookupError):
            raise
        except Exception as exc:
            raise PermissionError(
                "WebAuthn assertion verification failed"
            ) from exc

        return self.repository.commit_verified_authentication(
            user_id=user_id,
            challenge_record_id=challenge_record_id,
            credential_record_id=credential["id"],
            verified_sign_count=verified.new_sign_count,
        )

    def create_registration_options(
        self,
        *,
        user_id,
        user_name,
        user_display_name=None,
    ):
        """Create registration options and persist a hashed challenge."""
        self._require_enabled()

        if not isinstance(user_name, str) or not user_name.strip():
            raise ValueError("user_name must be a non-empty string")

        if user_display_name is None:
            user_display_name = user_name

        if (
            not isinstance(user_display_name, str)
            or not user_display_name.strip()
        ):
            raise ValueError("user_display_name must be a non-empty string")

        existing_credentials = self.repository.list_credentials(user_id)
        exclude_credentials = []

        for credential in existing_credentials:
            if credential["revoked_at"] is not None:
                continue

            raw_id = self._decode_stored_credential_id(
                credential["credential_id"]
            )

            try:
                transports = [
                    self._TRANSPORTS[item]
                    for item in credential["transports"]
                ]
            except (KeyError, TypeError) as exc:
                raise PermissionError(
                    "Stored passkey transport metadata is invalid"
                ) from exc

            exclude_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=raw_id,
                    transports=transports or None,
                )
            )

        raw_challenge = secrets.token_bytes(32)
        challenge_hash = hashlib.sha256(raw_challenge).hexdigest()

        options = generate_registration_options(
            rp_id=self.settings.webauthn_rp_id,
            rp_name=self.settings.webauthn_rp_name,
            user_name=user_name.strip(),
            user_id=user_id.encode("utf-8"),
            user_display_name=user_display_name.strip(),
            challenge=raw_challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=exclude_credentials,
        )

        challenge_expiry = (
            datetime.now(timezone.utc)
            + timedelta(
                seconds=self.settings.webauthn_challenge_ttl_seconds
            )
        )

        challenge = self.repository.create_challenge(
            user_id=user_id,
            challenge_hash=challenge_hash,
            purpose="registration",
            expires_at=challenge_expiry.isoformat(),
        )

        return {
            "challenge_record_id": challenge["id"],
            "options": json.loads(options_to_json(options)),
        }

    def verify_registration(
        self,
        *,
        user_id,
        challenge_record_id,
        credential,
        name=None,
    ):
        """Verify a registration response before atomically saving its key."""
        self._require_enabled()

        challenge = self.repository.get_challenge(
            user_id,
            challenge_record_id,
        )

        if challenge is None:
            raise LookupError("WebAuthn challenge not found")

        if (
            challenge["purpose"] != "registration"
            or challenge["consumed_at"] is not None
        ):
            raise PermissionError(
                "WebAuthn challenge is not available for registration"
            )

        challenge_expiry = self._parse_expiry(
            challenge["expires_at"],
            "WebAuthn registration challenge expiry",
        )

        if challenge_expiry <= datetime.now(timezone.utc):
            raise PermissionError("WebAuthn registration challenge has expired")

        # Browser-provided registration data remains untrusted until the
        # complete response is verified by the WebAuthn implementation.
        try:
            parsed_credential = parse_registration_credential_json(credential)

            client_data = parse_client_data_json(
                parsed_credential.response.client_data_json
            )

            if client_data.type != ClientDataType.WEBAUTHN_CREATE:
                raise PermissionError(
                    "Registration has an invalid client-data type"
                )

            if client_data.cross_origin is True:
                raise PermissionError(
                    "Cross-origin WebAuthn registrations are rejected"
                )

            supplied_challenge_hash = hashlib.sha256(
                client_data.challenge
            ).hexdigest()

            if not hmac.compare_digest(
                supplied_challenge_hash,
                challenge["challenge_hash"],
            ):
                raise PermissionError(
                    "WebAuthn registration challenge does not match"
                )

            verified = verify_registration_response(
                credential=parsed_credential,
                expected_challenge=client_data.challenge,
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=list(self.settings.webauthn_allowed_origins),
                require_user_presence=True,
                require_user_verification=True,
            )

            canonical_credential_id = bytes_to_base64url(
                verified.credential_id
            )

            if (
                parsed_credential.raw_id != verified.credential_id
                or parsed_credential.id != canonical_credential_id
            ):
                raise PermissionError(
                    "Verified registration credential ID does not match"
                )

            if not verified.user_verified:
                raise PermissionError(
                    "User verification is required for passkey registration"
                )

            transports = [
                item.value
                for item in (parsed_credential.response.transports or [])
            ]

            if any(item not in self._TRANSPORTS for item in transports):
                raise PermissionError(
                    "Registration contains an unsupported authenticator transport"
                )

        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError(
                "WebAuthn registration verification failed"
            ) from exc

        # The repository rechecks challenge ownership, purpose, expiry and
        # consumption inside the same transaction as credential insertion.
        return self.repository.commit_verified_registration(
            user_id=user_id,
            challenge_record_id=challenge_record_id,
            credential_id=canonical_credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            transports=transports,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
            name=name,
        )

