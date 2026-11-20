from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CapabilityStatus(str, Enum):
    REGISTERED = "registered"
    IMPLEMENTED = "implemented"
    AVAILABLE = "available"
    VERIFIED = "verified"


class LanguageCapability(str, Enum):
    LANGUAGE_DETECTION = "language_detection"
    TEXT_TRANSLATION = "text_translation"
    SPEECH_RECOGNITION = "speech_recognition"
    SPEECH_SYNTHESIS = "speech_synthesis"
    LIVE_TRANSLATION = "live_translation"


class CapabilityProfile(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: CapabilityStatus = CapabilityStatus.REGISTERED


class ScriptMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)
    code: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=100)
    direction: str = Field(pattern=r"^(ltr|rtl)$")


class DialectMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)
    code: str = Field(min_length=2, max_length=35)
    name: str = Field(min_length=1, max_length=100)

    @field_validator("code")
    @classmethod
    def validate_dialect_code(cls, value: str) -> str:
        if any(not part or "." in part for part in value.lower().split("-")):
            raise ValueError("Dialect code contains an invalid segment")
        return value.lower()


class LanguageEntry(BaseModel):
    model_config = ConfigDict(frozen=True)
    code: str = Field(min_length=2, max_length=35)
    name: str = Field(min_length=1, max_length=100)
    native_name: str = Field(min_length=1, max_length=100)
    script: ScriptMetadata
    dialects: tuple[DialectMetadata, ...] = Field(default_factory=tuple)
    capabilities: dict[LanguageCapability, CapabilityProfile]

    @field_validator("code")
    @classmethod
    def validate_language_code(cls, value: str) -> str:
        parts = value.lower().split("-")
        if not all(part and all(char.isalnum() for char in part) for part in parts):
            raise ValueError("Language code must contain alphanumeric BCP 47-style segments")
        return value.lower()

    @field_validator("native_name")
    @classmethod
    def validate_native_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Native name must not be blank")
        return value.strip()
