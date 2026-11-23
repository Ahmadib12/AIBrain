import threading
from dataclasses import dataclass
from typing import Callable

from backend.app.tools.contracts import (
    ExecutionIdempotencyMode,
    ExternalToolExecutionCapabilities,
    ExternalToolExecutionOutcome,
    ExternalToolOutcomeStatus,
)
from backend.app.tools.external import ExternalToolAction


class FakeProviderTimeout(TimeoutError):
    """Simulated lost response; the provider may already have applied the action."""


@dataclass(frozen=True)
class FakeProviderRecord:
    action_digest: str
    operation_reference: str
    result: dict


class FakeExternalToolProvider:
    """Deterministic in-memory provider for adapter conformance tests.

    It is intentionally not wired into the application gateway. The provider
    stores an operation before simulating a lost response, allowing tests to
    verify lookup and same-key deduplication without a second side effect.
    """

    def __init__(
        self,
        *,
        provider_id: str = "fake-provider",
        provider_scope: str = "fake-account",
        idempotency_mode: ExecutionIdempotencyMode = (
            ExecutionIdempotencyMode.PROVIDER_ENFORCED
        ),
        before_accept: Callable[[ExternalToolAction], None] | None = None,
    ) -> None:
        self._capabilities = ExternalToolExecutionCapabilities(
            provider_id=provider_id,
            adapter_id="fake-adapter",
            adapter_version="1",
            provider_scope=provider_scope,
            idempotency_mode=idempotency_mode,
            key_scope="provider-account-and-operation"
            if idempotency_mode is ExecutionIdempotencyMode.PROVIDER_ENFORCED
            else None,
            idempotency_retention_seconds=86_400
            if idempotency_mode is ExecutionIdempotencyMode.PROVIDER_ENFORCED
            else None,
            rejects_payload_mismatch=(
                idempotency_mode is ExecutionIdempotencyMode.PROVIDER_ENFORCED
            ),
            concurrent_deduplication=(
                idempotency_mode is ExecutionIdempotencyMode.PROVIDER_ENFORCED
            ),
            supports_outcome_lookup=True,
        )
        self._before_accept = before_accept
        self._records: dict[str, FakeProviderRecord] = {}
        self._lock = threading.Lock()
        self.dispatch_count = 0
        self.effect_count = 0
        self.lookup_count = 0
        self.timeout_after_accept_once = False

    @property
    def capabilities(self) -> ExternalToolExecutionCapabilities:
        return self._capabilities

    def execute(
        self,
        action: ExternalToolAction,
    ) -> ExternalToolExecutionOutcome:
        if not isinstance(action, ExternalToolAction):
            raise TypeError("Expected an ExternalToolAction")
        if self._before_accept is not None:
            self._before_accept(action)

        with self._lock:
            self.dispatch_count += 1
            existing = self._records.get(action.idempotency_key)
            if existing is not None:
                if existing.action_digest != action.action_digest:
                    raise ValueError("Idempotency key reused for a different action")
                return ExternalToolExecutionOutcome(
                    status=ExternalToolOutcomeStatus.SUCCEEDED,
                    operation_reference=existing.operation_reference,
                    result=dict(existing.result),
                    evidence_reference="fake-provider-idempotency-record",
                )

            if self.capabilities.idempotency_mode is ExecutionIdempotencyMode.NONE:
                # Non-idempotent mode deliberately cannot safely deduplicate.
                operation_reference = f"fake-operation-{self.effect_count + 1}"
            else:
                operation_reference = f"fake-operation-{self.effect_count + 1}"

            result = {"accepted": True, "payload": action.payload()}
            record = FakeProviderRecord(
                action_digest=action.action_digest,
                operation_reference=operation_reference,
                result=result,
            )
            self._records[action.idempotency_key] = record
            self.effect_count += 1

            if self.timeout_after_accept_once:
                self.timeout_after_accept_once = False
                raise FakeProviderTimeout("Response lost after provider acceptance")

            return ExternalToolExecutionOutcome(
                status=ExternalToolOutcomeStatus.SUCCEEDED,
                operation_reference=operation_reference,
                result=dict(result),
                evidence_reference="fake-provider-acceptance",
            )

    def lookup(self, idempotency_key: str) -> ExternalToolExecutionOutcome:
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("Idempotency key must be non-empty")
        with self._lock:
            self.lookup_count += 1
            record = self._records.get(idempotency_key)
            if record is None:
                return ExternalToolExecutionOutcome(
                    status=ExternalToolOutcomeStatus.UNKNOWN,
                    evidence_reference="fake-provider-no-record",
                )
            return ExternalToolExecutionOutcome(
                status=ExternalToolOutcomeStatus.SUCCEEDED,
                operation_reference=record.operation_reference,
                result=dict(record.result),
                evidence_reference="fake-provider-lookup",
            )
