"""Versioned event envelope for M15 streaming and M16 client transport."""
from datetime import datetime
from enum import Enum
import json
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventType(str, Enum):
    SESSION_ACCEPTED = "session.accepted"
    SESSION_REJECTED = "session.rejected"
    SESSION_CANCELLED = "session.cancelled"
    TRANSCRIPT_PARTIAL = "transcript.partial"
    TRANSCRIPT_FINAL = "transcript.final"
    TRANSLATION_PARTIAL = "translation.partial"
    TRANSLATION_FINAL = "translation.final"
    SPEECH_OUTPUT_STARTED = "speech.output.started"
    SPEECH_OUTPUT_COMPLETED = "speech.output.completed"
    DEVICE_STATE_CHANGED = "device.state_changed"
    SYNC_BATCH_ACCEPTED = "sync.batch_accepted"
    SYNC_CONFLICT = "sync.conflict"
    ERROR = "error"


class EventEnvelope(BaseModel):
    """JSON control event. Binary audio frames must travel outside this envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    session_id: UUID
    schema_version: int = Field(default=1, ge=1, le=100)
    event_type: EventType
    sequence: int = Field(ge=1)
    occurred_at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Event timestamp must be timezone-aware")
        return value

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 32:
            raise ValueError("Event payload cannot exceed 32 fields")
        try:
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ValueError("Event payload must be finite JSON data") from error
        if len(encoded) > 16_384:
            raise ValueError("Event payload cannot exceed 16384 bytes")
        return value
