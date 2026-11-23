from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Modality(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    DOCUMENT = "document"


class MediaReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    modality: Modality
    uri: str = Field(min_length=1, max_length=2048)
    mime_type: str = Field(min_length=1, max_length=100)
    size_bytes: int | None = Field(default=None, ge=0)


class StreamEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(min_length=1, max_length=100)
    sequence: int = Field(ge=0)
    payload: dict[str, Any] = Field(default_factory=dict, max_length=20)
