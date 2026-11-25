"""Fail-closed composition gate for production state-changing adapters.

Adapter registration is not certification or user authorization. Dispatch still
requires the persisted, matching operator-approved certification and the
one-time passkey authorization enforced by ExternalToolDispatcher.
"""
from __future__ import annotations

from dataclasses import dataclass

from backend.app.tools.contracts import (
    ExecutionIdempotencyMode,
    ExternalToolExecutionCapabilities,
)


@dataclass(frozen=True)
class ExternalActionReadinessEvidence:
    provider_id: str
    adapter_id: str
    adapter_version: str
    provider_scope: str
    verifier_id: str
    transport_id: str
    conformance_suite_id: str
    conformance_suite_version: str
    provider_verification_passed: bool
    transport_conformance_passed: bool
    idempotency_conformance_passed: bool
    outcome_lookup_conformance_passed: bool


class ExternalActionReadinessGate:
    REQUIRED_TRANSPORT_ID = "pinned-https-v1"

    @classmethod
    def validate(
        cls,
        capabilities: ExternalToolExecutionCapabilities,
        evidence: ExternalActionReadinessEvidence | None,
    ) -> None:
        if evidence is None:
            raise PermissionError(
                "Production external adapters require trusted readiness evidence"
            )
        expected = (
            capabilities.provider_id,
            capabilities.adapter_id,
            capabilities.adapter_version,
            capabilities.provider_scope,
        )
        supplied = (
            evidence.provider_id,
            evidence.adapter_id,
            evidence.adapter_version,
            evidence.provider_scope,
        )
        flags = (
            evidence.provider_verification_passed,
            evidence.transport_conformance_passed,
            evidence.idempotency_conformance_passed,
            evidence.outcome_lookup_conformance_passed,
        )
        if (
            supplied != expected
            or not isinstance(evidence.verifier_id, str)
            or not evidence.verifier_id.strip()
            or evidence.transport_id != cls.REQUIRED_TRANSPORT_ID
            or not isinstance(evidence.conformance_suite_id, str)
            or not evidence.conformance_suite_id.strip()
            or not isinstance(evidence.conformance_suite_version, str)
            or not evidence.conformance_suite_version.strip()
            or any(flag is not True for flag in flags)
            or capabilities.idempotency_mode is ExecutionIdempotencyMode.NONE
            or not capabilities.supports_outcome_lookup
        ):
            raise PermissionError(
                "Production external adapter security readiness is incomplete"
            )
