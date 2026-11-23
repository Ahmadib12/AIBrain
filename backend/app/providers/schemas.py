from enum import Enum
import json
import math
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


_SENSITIVE_METADATA_KEY = re.compile(
    r"(?:api[_-]?key|password|passwd|secret|credential|private[_-]?key"
    r"|authorization|bearer|token)",
    re.IGNORECASE,
)
_SENSITIVE_METADATA_VALUE = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|-----begin private key-----"
    r"|(?:api[_-]?key|password|passwd|secret|credential"
    r"|private[_-]?key|authorization|bearer|token)\s*[:=])",
)


def _validate_metadata_value(value: Any, *, depth: int = 0) -> None:
    if depth > 4:
        raise ValueError("Metadata nesting cannot exceed 4 levels")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Metadata cannot contain non-finite numbers")
        return
    if isinstance(value, str):
        if len(value) > 4_096:
            raise ValueError("Metadata string values are too large")
        if _SENSITIVE_METADATA_VALUE.search(value):
            raise ValueError("Sensitive metadata values are not allowed")
        return
    if isinstance(value, list):
        if len(value) > 20:
            raise ValueError("Metadata lists cannot exceed 20 items")
        for item in value:
            _validate_metadata_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 20:
            raise ValueError("Metadata objects cannot exceed 20 entries")
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("Metadata keys must be strings")
            if len(key) > 100:
                raise ValueError("Metadata keys are too long")
            if _SENSITIVE_METADATA_KEY.search(key):
                raise ValueError("Sensitive metadata keys are not allowed")
            _validate_metadata_value(nested, depth=depth + 1)
        return
    raise ValueError("Metadata contains an unsupported value type")


class ProviderAvailability(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(pattern=r"^(system|user|assistant)$")
    content: str = Field(min_length=1, max_length=100_000)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: list[ChatMessage] = Field(min_length=1, max_length=100)
    task_type: str = Field(default="general", min_length=1, max_length=100)
    model: str | None = Field(default=None, max_length=200)
    provider: str | None = Field(default=None, max_length=100)
    allow_fallback: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 20:
            raise ValueError("Metadata objects cannot exceed 20 entries")
        _validate_metadata_value(value)
        try:
            serialized = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise ValueError("Metadata must be valid JSON") from error
        if len(serialized.encode("utf-8")) > 4_096:
            raise ValueError("Metadata cannot exceed 4096 bytes")
        return value


class ChatResponse(BaseModel):
    content: str
    provider_id: str
    model_id: str
    latency_ms: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderInfo(BaseModel):
    id: str
    name: str
    enabled: bool
    priority: int
    models: tuple[str, ...]
    capabilities: tuple[str, ...]


class ProviderHealth(BaseModel):
    provider_id: str
    availability: ProviderAvailability
    last_success_at: str | None = None
    last_failure_at: str | None = None
    consecutive_failures: int = 0
    last_latency_ms: float | None = None


class ProviderFailure(BaseModel):
    provider_id: str
    error_code: str
    message: str
