"""Guarded external dispatch boundary.

This module is deliberately not wired into ToolExecutionGateway or application
routes. Adapters are resolved only from an application-configured trusted
registry, never supplied by an untrusted dispatch caller.
"""
from typing import Any

from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.tools.contracts import (
    ExternalToolExecutionOutcome,
    ExternalToolOutcomeStatus,
    ToolContract,
    ToolRisk,
    contract_fingerprint,
    execution_action_digest,
)
from backend.app.tools.external import ExternalToolAction, ExternalToolAdapter


def _capability_snapshot(adapter: ExternalToolAdapter) -> dict[str, Any]:
    capabilities = adapter.capabilities
    return {
        "idempotency_mode": capabilities.idempotency_mode.value,
        "key_scope": capabilities.key_scope,
        "idempotency_retention_seconds": capabilities.idempotency_retention_seconds,
        "rejects_payload_mismatch": capabilities.rejects_payload_mismatch,
        "concurrent_deduplication": capabilities.concurrent_deduplication,
        "supports_outcome_lookup": capabilities.supports_outcome_lookup,
    }


class ExternalToolAdapterRegistry:
    """Trusted, application-configured adapter registry keyed by tool ID."""

    def __init__(self) -> None:
        self._adapters: dict[str, ExternalToolAdapter] = {}

    def register(self, tool_id: str, adapter: ExternalToolAdapter) -> None:
        if not isinstance(tool_id, str) or not tool_id.strip():
            raise ValueError("Tool ID must be a non-empty string")
        if not isinstance(adapter, ExternalToolAdapter):
            raise TypeError("A conforming external adapter is required")
        if tool_id in self._adapters:
            raise ValueError("An external adapter is already registered for this tool")
        self._adapters[tool_id] = adapter

    def get(self, tool_id: str) -> ExternalToolAdapter | None:
        return self._adapters.get(tool_id)


class ExternalToolDispatcher:
    """One-shot external dispatcher; unknown outcomes are never retried."""

    def __init__(
        self,
        repository: ToolRequestRepository,
        adapters: ExternalToolAdapterRegistry,
    ) -> None:
        self.repository = repository
        self.adapters = adapters

    def dispatch(
        self,
        user_id: str,
        request_id: str,
        *,
        contract: ToolContract,
    ) -> dict:
        if not isinstance(contract, ToolContract):
            raise TypeError("A registered ToolContract is required")
        if contract.risk is not ToolRisk.STATE_CHANGE:
            raise PermissionError("External dispatch requires a state-change contract")
        fingerprint = contract_fingerprint(contract)
        adapter = self.adapters.get(contract.tool_id)
        if adapter is None:
            raise PermissionError("No trusted external adapter is registered")
        capabilities = adapter.capabilities
        snapshot = _capability_snapshot(adapter)
        certification = self.repository.get_active_external_adapter_certification(
            provider_id=capabilities.provider_id,
            adapter_id=capabilities.adapter_id,
            adapter_version=capabilities.adapter_version,
            provider_scope=capabilities.provider_scope,
            capabilities=snapshot,
        )
        if certification is None:
            raise PermissionError(
                "External adapter has no active, matching sandbox certification"
            )
        proposed = self.repository.get(user_id, request_id)
        if proposed["tool_id"] != contract.tool_id:
            raise PermissionError("Tool contract does not match the authorized request")
        if proposed["contract_fingerprint"] != fingerprint:
            raise PermissionError("Tool contract changed after authorization")
        claimed = self.repository.claim_passkey_authorized_for_execution(
            user_id,
            request_id,
            expected_contract_fingerprint=fingerprint,
        )
        payload = claimed["arguments"]
        adapter_id = capabilities.adapter_id
        adapter_version = capabilities.adapter_version
        provider_id = capabilities.provider_id
        provider_scope = capabilities.provider_scope
        digest = execution_action_digest(
            user_id=user_id,
            tool_id=contract.tool_id,
            arguments=payload,
            contract_fingerprint=fingerprint,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            provider_id=provider_id,
            provider_scope=provider_scope,
        )
        binding = self.repository.create_execution_binding(
            user_id,
            request_id,
            idempotency_key=request_id,
            action_digest=digest,
            payload=payload,
            tool_contract_fingerprint=fingerprint,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            provider_id=provider_id,
            provider_scope=provider_scope,
            capabilities=snapshot,
        )
        action = ExternalToolAction(
            idempotency_key=binding["idempotency_key"],
            action_digest=binding["action_digest"],
            payload_json=binding["payload_json"],
        )
        # This transaction is the final authorization + binding check and
        # records a unique dispatch_started event before crossing the boundary.
        frozen = self.repository.begin_external_dispatch(
            user_id,
            request_id,
            expected_contract_fingerprint=fingerprint,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            provider_id=provider_id,
            provider_scope=provider_scope,
            capabilities=snapshot,
        )
        if frozen["action_digest"] != action.action_digest:
            raise PermissionError("Frozen dispatch digest changed")

        try:
            outcome = adapter.execute(action)
        except Exception:
            # A transport exception does not prove the provider did not act.
            # Keep the operation unknown and require explicit reconciliation.
            self.repository.record_external_dispatch_outcome(
                user_id,
                request_id,
                outcome="unknown",
                action_digest=digest,
                error_code="provider_outcome_unknown",
            )
            return {
                "status": "outcome_unknown",
                "request_id": request_id,
                "automatic_retry": False,
            }

        if not isinstance(outcome, ExternalToolExecutionOutcome):
            self.repository.record_external_dispatch_outcome(
                user_id,
                request_id,
                outcome="unknown",
                action_digest=digest,
                error_code="invalid_provider_outcome",
            )
            return {
                "status": "outcome_unknown",
                "request_id": request_id,
                "automatic_retry": False,
            }

        if outcome.status is ExternalToolOutcomeStatus.SUCCEEDED:
            self.repository.record_external_dispatch_outcome(
                user_id,
                request_id,
                outcome="succeeded",
                action_digest=digest,
                result=outcome.result,
                evidence_reference=(
                    outcome.evidence_reference or outcome.operation_reference
                ),
            )
            return {
                "status": "completed",
                "request_id": request_id,
                "operation_reference": outcome.operation_reference,
                "result": outcome.result,
            }

        if outcome.status is ExternalToolOutcomeStatus.FAILED:
            self.repository.record_external_dispatch_outcome(
                user_id,
                request_id,
                outcome="failed",
                action_digest=digest,
                error_code=outcome.error_code,
                evidence_reference=outcome.evidence_reference,
            )
            return {"status": "failed", "request_id": request_id}

        self.repository.record_external_dispatch_outcome(
            user_id,
            request_id,
            outcome="unknown",
            action_digest=digest,
            error_code="provider_reported_unknown",
            evidence_reference=outcome.evidence_reference,
        )
        return {
            "status": "outcome_unknown",
            "request_id": request_id,
            "automatic_retry": False,
        }

    def lookup(
        self,
        user_id: str,
        request_id: str,
    ) -> ExternalToolExecutionOutcome:
        """Read provider state only; this method never executes or retries."""
        request = self.repository.get(user_id, request_id)
        adapter = self.adapters.get(request["tool_id"])
        if adapter is None:
            raise PermissionError("No trusted external adapter is registered")
        binding = self.repository.get_execution_binding(user_id, request_id)
        attempt = self.repository.get_execution_attempt(user_id, request_id)
        if attempt["status"] != "outcome_unknown":
            raise PermissionError("Provider lookup is reserved for unknown outcomes")
        capabilities = adapter.capabilities
        if not capabilities.supports_outcome_lookup:
            raise PermissionError("Adapter does not support outcome lookup")
        if (
            binding["adapter_id"] != capabilities.adapter_id
            or binding["adapter_version"] != capabilities.adapter_version
            or binding["provider_id"] != capabilities.provider_id
            or binding["provider_scope"] != capabilities.provider_scope
            or binding["capabilities"] != _capability_snapshot(adapter)
        ):
            raise PermissionError("Lookup adapter does not match persisted binding")
        outcome = adapter.lookup(binding["idempotency_key"])
        if not isinstance(outcome, ExternalToolExecutionOutcome):
            raise TypeError("Adapter returned an invalid lookup outcome")
        self.repository.record_external_outcome_lookup(
            user_id,
            request_id,
            action_digest=binding["action_digest"],
            outcome=outcome.status.value,
            evidence_reference=outcome.evidence_reference or outcome.operation_reference,
        )
        # Even a positive lookup is evidence for a separate reconciliation
        # decision; it does not silently rewrite the request's terminal state.
        return outcome
