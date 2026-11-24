"""Trusted composition gate for production provider adapters.

Readiness evidence is supplied only by application composition, never by an
API request. This is a fail-closed registration boundary, not a substitute for
independent provider-specific security review.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderReadinessEvidence:
    integration_id: str
    verifier_id: str
    transport_id: str
    conformance_suite_version: str
    verified_scopes: tuple[str, ...]
    provider_verification_passed: bool
    transport_conformance_passed: bool


class ProviderReadinessGate:
    REQUIRED_TRANSPORT_ID = "pinned-https-v1"
    REQUIRED_SUITE_VERSION = "m10.11-m10.13"

    @classmethod
    def validate(
        cls,
        integration_id: str,
        evidence: ProviderReadinessEvidence | None,
    ) -> None:
        if evidence is None:
            raise PermissionError("Production provider registration requires readiness evidence")
        if (
            evidence.integration_id != integration_id
            or not isinstance(evidence.verifier_id, str)
            or not evidence.verifier_id.strip()
            or evidence.transport_id != cls.REQUIRED_TRANSPORT_ID
            or evidence.conformance_suite_version != cls.REQUIRED_SUITE_VERSION
            or not isinstance(evidence.verified_scopes, tuple)
            or not evidence.verified_scopes
            or any(not isinstance(scope, str) or not scope.strip() for scope in evidence.verified_scopes)
            or len(set(evidence.verified_scopes)) != len(evidence.verified_scopes)
            or evidence.provider_verification_passed is not True
            or evidence.transport_conformance_passed is not True
        ):
            raise PermissionError("Production provider security readiness is incomplete")
