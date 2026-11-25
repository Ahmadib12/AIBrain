"""M16 synchronization wire contracts.

These schemas carry opaque encrypted payloads. They do not claim end-to-end
encryption: key establishment, authorization, and encryption are separate services.
"""
import base64
from datetime import datetime
from enum import Enum
import hashlib
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
        if value is None:
            return value
        if not value or not _B64.fullmatch(value):
            raise ValueError("Ciphertext must be base64 encoded")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError("Ciphertext must be valid base64") from error
        if not decoded or len(decoded) > 65_536:
            raise ValueError("Ciphertext must contain between 1 and 65536 bytes")
        return value

    @model_validator(mode="after")
    def validate_payload_binding(self):
        fields = (self.ciphertext_b64, self.ciphertext_sha256, self.key_reference)
        if self.operation == SyncOperationKind.DELETE:
            if any(value is not None for value in fields):
                raise ValueError("Delete operations must not carry a payload or key reference")
            return self
        if any(value is None for value in fields):
            raise ValueError("Upsert operations require ciphertext, digest, and key reference")
        decoded = base64.b64decode(self.ciphertext_b64, validate=True)
        digest = hashlib.sha256(decoded).hexdigest()
        if digest != self.ciphertext_sha256:
            raise ValueError("Ciphertext digest does not match payload")
        if not self.key_reference.strip():
            raise ValueError("Key reference must not be blank")
        return self


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
