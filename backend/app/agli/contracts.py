"""Provider-neutral contracts for AGLI text and speech capabilities.

These models describe requests and results only. They do not register engines,
grant consent, capture audio, or assert that a capability is available.
"""
from enum import Enum
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


_LANGUAGE_TAG = r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"


class ProcessingPreference(str, Enum):
    LOCAL_ONLY = "local_only"
    LOCAL_PREFERRED = "local_preferred"
    CLOUD_ALLOWED = "cloud_allowed"


class AudioEncoding(str, Enum):
    PCM_S16LE = "pcm_s16le"
    OPUS = "opus"
    AAC = "aac"


class LanguageDetectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1, max_length=20_000)
    data_classification: DataClassification = DataClassification.CONFIDENTIAL
    processing_preference: ProcessingPreference = ProcessingPreference.LOCAL_ONLY

    @field_validator("text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Text must not be blank")
        return value


class LanguageDetectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    confidence: float = Field(ge=0.0, le=1.0)
    engine_id: str = Field(min_length=1, max_length=100)
    engine_version: str = Field(min_length=1, max_length=100)


class TranslationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1, max_length=20_000)
    source_language: str | None = Field(default=None, pattern=_LANGUAGE_TAG, max_length=35)
    target_language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    context: str | None = Field(default=None, max_length=2_000)
    data_classification: DataClassification = DataClassification.CONFIDENTIAL
    processing_preference: ProcessingPreference = ProcessingPreference.LOCAL_ONLY

    @field_validator("text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Text must not be blank")
        return value


class TranslationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    translated_text: str = Field(min_length=1, max_length=40_000)
    source_language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    target_language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    engine_id: str = Field(min_length=1, max_length=100)
    engine_version: str = Field(min_length=1, max_length=100)


class SpeechSessionRequest(BaseModel):
    """Metadata-only session request; audio bytes use a separate media transport."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: UUID
    source_language: str | None = Field(default=None, pattern=_LANGUAGE_TAG, max_length=35)
    target_language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    encoding: AudioEncoding
    sample_rate_hz: int = Field(ge=8_000, le=96_000)
    channels: int = Field(ge=1, le=2)
    max_duration_seconds: int = Field(default=300, ge=1, le=3_600)
    data_classification: DataClassification = DataClassification.CONFIDENTIAL
    processing_preference: ProcessingPreference = ProcessingPreference.LOCAL_ONLY
    # Consent is checked by the server-side policy service, never trusted from
    # this request body. This field intentionally contains no consent claim.


class TranscriptSegment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    segment_id: UUID
    start_ms: int = Field(ge=0)
    end_ms: int = Field(ge=0)
    text: str = Field(min_length=1, max_length=8_000)
    language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    confidence: float = Field(ge=0.0, le=1.0)
    is_final: bool

    @field_validator("end_ms")
    @classmethod
    def validate_time_order(cls, value: int, info) -> int:
        start = info.data.get("start_ms")
        if start is not None and value < start:
            raise ValueError("Segment end must not precede its start")
        return value


class SpeechEngine(Protocol):
    """Trusted runtime adapter contract; implementations are composition-owned."""

    async def recognize(self, request: SpeechSessionRequest) -> TranscriptSegment:
        ...


class TranslationEngine(Protocol):
    async def detect(
        self,
        request: LanguageDetectionRequest,
    ) -> LanguageDetectionResult:
        ...

    async def translate(self, request: TranslationRequest) -> TranslationResult:
        ...
