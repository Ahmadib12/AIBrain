import json
import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from backend.app.tools.contracts import (
    ExternalToolExecutionCapabilities,
    ExternalToolExecutionOutcome,
)


_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ExternalToolAction:
    """Immutable, canonical action envelope passed to an external adapter."""

    idempotency_key: str
    action_digest: str
    payload_json: str

    def __post_init__(self) -> None:
        if not isinstance(self.idempotency_key, str) or not self.idempotency_key.strip():
            raise ValueError("Idempotency key must be a non-empty string")
        if not isinstance(self.action_digest, str) or not _DIGEST_PATTERN.fullmatch(
            self.action_digest
        ):
            raise ValueError("Action digest must be a lowercase SHA-256 hex digest")
        if not isinstance(self.payload_json, str):
            raise ValueError("Action payload must be canonical JSON text")
        try:
            payload = json.loads(self.payload_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Action payload must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("Action payload must be a JSON object")
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if canonical != self.payload_json:
            raise ValueError("Action payload JSON must be canonical")

    @classmethod
    def from_payload(
        cls,
        *,
        idempotency_key: str,
        action_digest: str,
        payload: dict[str, Any],
    ) -> "ExternalToolAction":
        if not isinstance(payload, dict):
            raise ValueError("Action payload must be an object")
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return cls(
            idempotency_key=idempotency_key,
            action_digest=action_digest,
            payload_json=payload_json,
        )

    def payload(self) -> dict[str, Any]:
        """Return a fresh payload object so callers cannot mutate this action."""
        return json.loads(self.payload_json)


@runtime_checkable
class ExternalToolAdapter(Protocol):
    """Provider-neutral boundary; lookup must never dispatch or retry."""

    @property
    def capabilities(self) -> ExternalToolExecutionCapabilities:
        ...

    def execute(
        self,
        action: ExternalToolAction,
    ) -> ExternalToolExecutionOutcome:
        ...

    def lookup(
        self,
        idempotency_key: str,
    ) -> ExternalToolExecutionOutcome:
        ...
