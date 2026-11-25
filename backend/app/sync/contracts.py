"""M16 synchronization wire contracts.

These schemas carry opaque encrypted payloads. They do not claim end-to-end
encryption: key establishment, authorization, and encryption are separate services.
"""
from datetime import datetime
from enum import Enum
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class SyncEntityType(str, Enum):
    MEMORY = "memory"
    PREFERENCE = "preference"
    GOAL = "goal"
    PROJECT = "project"
    USER_SETTING = "user_setting"


class SyncOperationKind(str, Enum):
    UPSERT = "upsert"
    DELETE = "delete"


class SyncOperation(BaseModel):
    """An idempotent, versioned operation with an opaque payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: UUID
    entity_id: UUID
    entity_type: SyncEntityType
    operation: SyncOperationKind
    entity_version: int = Field(ge=1)
    schema_version: int = Field(ge=1, le=100)
    occurred_at: datetime
    ciphertext_b64: str | None = Field(default=None, max_length=87_384)
    ciphertext_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    key_reference: str | None = Field(default=None, min_length=1, max_length=120)

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Sync timestamp must be timezone-aware")
        return value

    @field_validator("ciphertext_b64")
    @classmethod
    def validate_ciphertext_encoding(cls, value: str | None) -> str | None:
        if value is not None and (not value or not _B64.fullmatch(value)):
            raise ValueError("Ciphertext must be base64 encoded")
        return value

    @field_validator("ciphertext_sha256")
    @classmethod
    def validate_ciphertext_digest(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.fullmatch(value):
            raise ValueError("Ciphertext digest must be a lowercase SHA-256 hex value")
        return value

    @field_validator("key_reference")
    @classmethod
    def validate_key_reference(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("Key reference must not be blank")
        return value

    @field_validator("operation")
    @classmethod
    def require_delete_without_payload(cls, value: SyncOperationKind, info):
        # Cross-field validation is performed by the model validator below.
        return value


class SyncBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: UUID
    cursor: str | None = Field(default=None, max_length=512)
    operations: tuple[SyncOperation, ...] = Field(min_length=1, max_length=100)


class SyncBatchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    accepted_operation_ids: tuple[UUID, ...] = Field(max_length=100)
    next_cursor: str | None = Field(default=None, max_length=512)
    has_more: bool = False
