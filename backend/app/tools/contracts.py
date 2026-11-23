import copy
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ToolRisk(str, Enum):
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    CONSEQUENTIAL = "consequential"


@dataclass(frozen=True)
class ToolContract:
    tool_id: str
    name: str
    description: str
    risk: ToolRisk
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    version: int = 1

    def __post_init__(self) -> None:
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version < 1
        ):
            raise ValueError("Tool contract version must be a positive integer")


def contract_fingerprint(contract: ToolContract) -> str:
    canonical_contract = {
        "tool_id": contract.tool_id,
        "name": contract.name,
        "description": contract.description,
        "risk": contract.risk.value,
        "version": contract.version,
        "input_schema": contract.input_schema,
        "output_schema": contract.output_schema,
    }

    canonical_json = json.dumps(
        canonical_contract,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(canonical_json).hexdigest()


class ExecutionIdempotencyMode(str, Enum):
    NONE = "none"
    PROVIDER_ENFORCED = "provider_enforced"


class ExternalToolOutcomeStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ExternalToolExecutionCapabilities:
    """Provider guarantees declared by one specific external tool adapter.

    These declarations are claims that require provider documentation and
    adapter conformance evidence; the type itself does not verify a provider.
    """

    provider_id: str
    adapter_id: str
    adapter_version: str
    provider_scope: str
    idempotency_mode: ExecutionIdempotencyMode
    key_scope: str | None = None
    idempotency_retention_seconds: int | None = None
    rejects_payload_mismatch: bool = False
    concurrent_deduplication: bool = False
    supports_outcome_lookup: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "provider_id",
            "adapter_id",
            "adapter_version",
            "provider_scope",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")

        if not isinstance(self.idempotency_mode, ExecutionIdempotencyMode):
            raise ValueError("Unsupported idempotency mode")

        if not isinstance(self.supports_outcome_lookup, bool):
            raise ValueError("supports_outcome_lookup must be a boolean")

        if self.idempotency_mode == ExecutionIdempotencyMode.NONE:
            if (
                self.key_scope is not None
                or self.idempotency_retention_seconds is not None
                or self.rejects_payload_mismatch
                or self.concurrent_deduplication
            ):
                raise ValueError(
                    "Non-idempotent adapters cannot declare provider key guarantees"
                )
            return

        if not isinstance(self.key_scope, str) or not self.key_scope.strip():
            raise ValueError(
                "Provider-enforced idempotency requires a key scope"
            )
        if (
            isinstance(self.idempotency_retention_seconds, bool)
            or not isinstance(self.idempotency_retention_seconds, int)
            or self.idempotency_retention_seconds <= 0
        ):
            raise ValueError(
                "Provider-enforced idempotency requires a positive retention period"
            )
        if self.rejects_payload_mismatch is not True:
            raise ValueError(
                "Provider must reject same-key requests with different payloads"
            )
        if self.concurrent_deduplication is not True:
            raise ValueError(
                "Provider must guarantee deduplication for concurrent same-key requests"
            )


@dataclass(frozen=True)
class ExternalToolExecutionOutcome:
    """Normalized adapter outcome; UNKNOWN is not a retry instruction."""

    status: ExternalToolOutcomeStatus
    operation_reference: str | None = None
    result: dict[str, Any] | None = None
    error_code: str | None = None
    evidence_reference: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ExternalToolOutcomeStatus):
            raise ValueError("Unsupported external execution outcome")

        if self.operation_reference is not None and (
            not isinstance(self.operation_reference, str)
            or not self.operation_reference.strip()
        ):
            raise ValueError("operation_reference must be a non-empty string")

        if self.evidence_reference is not None and (
            not isinstance(self.evidence_reference, str)
            or not self.evidence_reference.strip()
        ):
            raise ValueError("evidence_reference must be a non-empty string")

        if self.error_code is not None and (
            not isinstance(self.error_code, str)
            or not self.error_code.strip()
            or len(self.error_code) > 64
        ):
            raise ValueError("error_code must contain 1 to 64 characters")

        if self.status == ExternalToolOutcomeStatus.SUCCEEDED:
            if not self.operation_reference:
                raise ValueError("Succeeded outcome requires an operation reference")
            if not isinstance(self.result, dict):
                raise ValueError("Succeeded outcome requires a result object")
            if self.error_code is not None:
                raise ValueError("Succeeded outcome cannot include an error code")
        elif self.status == ExternalToolOutcomeStatus.FAILED:
            if not self.error_code:
                raise ValueError("Failed outcome requires an error code")
            if self.result is not None:
                raise ValueError("Failed outcome cannot include a result")
        else:
            if self.result is not None or self.error_code is not None:
                raise ValueError(
                    "Unknown outcome cannot claim a result or definitive error"
                )


def execution_action_digest(
    *,
    user_id: str,
    tool_id: str,
    arguments: dict[str, Any],
    contract_fingerprint: str,
    adapter_id: str,
    adapter_version: str,
    provider_scope: str,
) -> str:
    """Bind one logical action to its owner, contract, adapter, and provider scope."""
    values = {
        "user_id": user_id,
        "tool_id": tool_id,
        "contract_fingerprint": contract_fingerprint,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "provider_scope": provider_scope,
    }
    if any(
        not isinstance(value, str) or not value.strip()
        for value in values.values()
    ):
        raise ValueError("Action binding identifiers must be non-empty strings")
    if not isinstance(arguments, dict):
        raise ValueError("Action arguments must be an object")

    canonical_action = {
        **values,
        "arguments": arguments,
    }
    canonical_json = json.dumps(
        canonical_action,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical_json).hexdigest()


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolContract] = {}

    def register(self, contract: ToolContract) -> None:
        if contract.tool_id in self._tools:
            raise ValueError("Tool is already registered")
        self._tools[contract.tool_id] = copy.deepcopy(contract)

    def get(self, tool_id: str) -> ToolContract | None:
        contract = self._tools.get(tool_id)
        return copy.deepcopy(contract) if contract is not None else None

    def list(self) -> tuple[ToolContract, ...]:
        return tuple(
            copy.deepcopy(contract)
            for contract in sorted(
                self._tools.values(),
                key=lambda contract: contract.tool_id,
            )
        )
