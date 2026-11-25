"""Provider-neutral contracts for AGLI text and speech capabilities.

These models describe requests and results only. They do not register engines,
grant consent, capture audio, or assert that a capability is available.
"""
from collections.abc import AsyncIterator
from enum import Enum
import re
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.agli.schemas import LanguageCapability


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



class EngineExecutionLocation(str, Enum):
    LOCAL = "local"
    CLOUD = "cloud"


class EngineCapabilityState(str, Enum):
    REGISTERED = "registered"
    IMPLEMENTED = "implemented"
    AVAILABLE = "available"
    VERIFIED = "verified"
    DISABLED = "disabled"


class LanguagePair(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    target_language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)


class EngineCapabilityProfile(BaseModel):
    """Trusted composition metadata; a status is not proof by itself."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engine_id: str = Field(min_length=1, max_length=100)
    engine_version: str = Field(min_length=1, max_length=100)
    capability: LanguageCapability
    state: EngineCapabilityState = EngineCapabilityState.REGISTERED
    execution_location: EngineExecutionLocation
    supported_languages: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    supported_language_pairs: tuple[LanguagePair, ...] = Field(default_factory=tuple, max_length=500)
    evaluation_suite_id: str | None = Field(default=None, max_length=120)
    evaluation_suite_version: str | None = Field(default=None, max_length=80)

    @field_validator("supported_languages")
    @classmethod
    def validate_supported_languages(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.lower() for value in values)
        if any(not re.fullmatch(_LANGUAGE_TAG, value) for value in normalized):
            raise ValueError("Supported languages must use valid language tags")
        if len(set(normalized)) != len(normalized):
            raise ValueError("Supported languages must be unique")
        return normalized

    @model_validator(mode="after")
    def require_evaluation_for_verified_state(self):
        if self.state == EngineCapabilityState.VERIFIED:
            if not self.evaluation_suite_id or not self.evaluation_suite_version:
                raise ValueError("Verified capability requires evaluation suite identity and version")
        return self


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


class SpeechSynthesisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1, max_length=8_000)
    language: str = Field(pattern=_LANGUAGE_TAG, max_length=35)
    encoding: AudioEncoding
    voice_id: str | None = Field(default=None, min_length=1, max_length=100)


class SpeechEngine(Protocol):
    """Trusted runtime adapter contract; implementations are composition-owned."""

    def recognize(
        self,
        request: SpeechSessionRequest,
    ) -> AsyncIterator[TranscriptSegment]:
        ...


class SpeechSynthesisEngine(Protocol):
    """Audio bytes are streamed separately, never embedded in JSON events."""

    def synthesize(self, request: SpeechSynthesisRequest) -> AsyncIterator[bytes]:
        ...


class TranslationEngine(Protocol):
    async def detect(
        self,
        request: LanguageDetectionRequest,
    ) -> LanguageDetectionResult:
        ...

    async def translate(self, request: TranslationRequest) -> TranslationResult:
        ...
