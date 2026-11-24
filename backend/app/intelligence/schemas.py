from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.intelligence.trace import DecisionTrace


class TaskType(str, Enum):
    CONVERSATION = "conversation"
    LANGUAGE_LOOKUP = "language_lookup"
    PROVIDER_STATUS = "provider_status"
    UNSUPPORTED = "unsupported"


class ClassificationStatus(str, Enum):
    EXPLICIT = "explicit"
    DEFAULT = "default"
    UNSUPPORTED = "unsupported"


class ResponseStatus(str, Enum):
    COMPLETED = "completed"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class ContextRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"


class CapabilityStatus(str, Enum):
    REGISTERED = "registered"
    IMPLEMENTED = "implemented"
    AVAILABLE = "available"


_CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|password|passwd|secret|credential"
    r"|private[_-]?key|authorization|bearer|token)\b\s*[:=]"
)
_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}\b"
)


def contains_credential_content(value: str) -> bool:
    lowered = value.lower()
    if "-----begin private key-----" in lowered:
        return True
    return bool(
        _CREDENTIAL_ASSIGNMENT_PATTERN.search(value)
        or _SENSITIVE_VALUE_PATTERN.search(value)
    )


def contains_sensitive_metadata_key(value: Any) -> bool:
    sensitive_terms = (
        "api_key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "credential",
        "private_key",
        "authorization",
        "bearer",
        "token",
    )
    if isinstance(value, dict):
        for key, nested_value in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(term in normalized for term in sensitive_terms):
                return True
            if contains_sensitive_metadata_key(nested_value):
                return True
    elif isinstance(value, list):
        return any(contains_sensitive_metadata_key(item) for item in value)
    elif isinstance(value, tuple):
        return any(contains_sensitive_metadata_key(item) for item in value)
    elif isinstance(value, str):
        return contains_credential_content(value)
    return False


class IntelligenceMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: ContextRole
    content: str = Field(min_length=1, max_length=100_000)

    @field_validator("content")
    @classmethod
    def validate_public_message_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message content must not be blank")
        if contains_credential_content(value):
            raise ValueError("Credentials cannot be included in intelligence messages")
        return value


class ContextTurn(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: ContextRole
    content: str = Field(min_length=1, max_length=100_000)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Context turn content must not be blank")
        if contains_credential_content(value):
            raise ValueError("Credentials cannot be stored in conversation context")
        return value


class ConversationContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    context_id: str = Field(
        default_factory=lambda: str(uuid4()),
        min_length=1,
        max_length=100,
    )
    turns: tuple[ContextTurn, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )

    @field_validator("context_id")
    @classmethod
    def validate_context_id(cls, value: str) -> str:
        if contains_credential_content(value):
            raise ValueError("Credentials cannot be used as a context identifier")
        return value

    @field_validator("turns")
    @classmethod
    def validate_turn_count(
        cls,
        value: tuple[ContextTurn, ...],
    ) -> tuple[ContextTurn, ...]:
        if len(value) > 20:
            raise ValueError("Conversation context cannot exceed 20 turns")
        return value


class IntelligenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: tuple[IntelligenceMessage, ...] = Field(
        min_length=1,
        max_length=100,
    )
    context_id: str | None = Field(default=None, max_length=100)
    task_type: str | None = Field(default=None, max_length=100)
    language_code: str | None = Field(default=None, max_length=35)
    provider: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=200)
    allow_fallback: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=20)

    @field_validator("context_id")
    @classmethod
    def validate_context_id(cls, value: str | None) -> str | None:
        if value is not None and contains_credential_content(value):
            raise ValueError("Credentials cannot be used as a context identifier")
        return value

    @field_validator("language_code")
    @classmethod
    def validate_language_code(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower().strip()
        parts = normalized.split("-")
        if not parts or not all(
            part and all(char.isalnum() for char in part)
            for part in parts
        ):
            raise ValueError("Language code must use BCP 47-style segments")
        return normalized

    @field_validator("messages")
    @classmethod
    def validate_messages(
        cls,
        value: tuple[IntelligenceMessage, ...],
    ) -> tuple[IntelligenceMessage, ...]:
        if len(value) > 100:
            raise ValueError("Request cannot contain more than 100 messages")
        return value

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if contains_sensitive_metadata_key(value):
            raise ValueError(
                "Sensitive credentials cannot be provided in metadata"
            )
        try:
            serialized = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as error:
            raise ValueError("Request metadata must be valid JSON") from error

        if len(serialized.encode("utf-8")) > 4_096:
            raise ValueError("Request metadata is too large")
        return value


class TaskClassification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_type: TaskType
    status: ClassificationStatus
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=500)


class CapabilityMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=150)
    description: str = Field(default="", max_length=1_000)
    registered: bool = True
    implemented: bool = False
    available: bool = False

    @field_validator("capability_id")
    @classmethod
    def validate_capability_id(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
            for char in normalized
        ):
            raise ValueError(
                "Capability ID must contain lowercase letters, digits, "
                "hyphen, or underscore"
            )
        return normalized

    @model_validator(mode="after")
    def validate_status_consistency(self) -> "CapabilityMetadata":
        if not self.registered:
            raise ValueError("Registered capabilities must have registered=True")
        if self.available and not self.implemented:
            raise ValueError("Available capabilities must also be implemented")
        return self

    @property
    def status(self) -> CapabilityStatus:
        if self.available:
            return CapabilityStatus.AVAILABLE
        if self.implemented:
            return CapabilityStatus.IMPLEMENTED
        return CapabilityStatus.REGISTERED


class IntelligenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    decision_trace: DecisionTrace | None = None
    planning: dict[str, Any] | None = None
    task_type: TaskType
    status: ResponseStatus
    content: str | None = Field(default=None, max_length=100_000)
    selected_capabilities: tuple[str, ...] = Field(
        default_factory=tuple,
        max_length=50,
    )
    warnings: tuple[str, ...] = Field(default_factory=tuple, max_length=50)
    error_code: str | None = Field(default=None, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=20)
