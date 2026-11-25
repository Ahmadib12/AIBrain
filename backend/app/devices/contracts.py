"""M16 device identity and capability declaration contracts.

Client capability declarations are descriptive input, not authorization grants.
"""
from datetime import datetime
from enum import Enum
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


_FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")


class DevicePlatform(str, Enum):
    ANDROID = "android"
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"


class DeviceLifecycleStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class DeviceCapability(str, Enum):
    MICROPHONE = "microphone"
    AUDIO_OUTPUT = "audio_output"
    NOTIFICATIONS = "notifications"
    ACCESSIBILITY = "accessibility"
    LOCAL_INFERENCE = "local_inference"
    FILE_PICKER = "file_picker"
    VOIP_MEDIA = "voip_media"


class DeviceRegistrationRequest(BaseModel):
    """Enrollment intent. Server-side authentication/confirmation is still required."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: DevicePlatform
    app_version: str = Field(min_length=1, max_length=50)
    display_name: str | None = Field(default=None, max_length=80)
    public_key_fingerprint: str = Field(pattern=r"^[a-fA-F0-9]{64}$")

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Display name must not be blank")
        return value


class DeviceCapabilityReport(BaseModel):
    """Untrusted client report; never use it as proof of OS permission."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capabilities: tuple[DeviceCapability, ...] = Field(max_length=20)
    reported_at: datetime

    @field_validator("reported_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Capability report timestamp must be timezone-aware")
        return value


class DeviceRecord(BaseModel):
    """Server-owned device projection. Secrets and private keys are never included."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: UUID
    owner_id: UUID
    platform: DevicePlatform
    app_version: str = Field(min_length=1, max_length=50)
    display_name: str | None = Field(default=None, max_length=80)
    public_key_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: DeviceLifecycleStatus
    enrolled_at: datetime
    last_seen_at: datetime | None = None
    revoked_at: datetime | None = None

    @field_validator("enrolled_at", "last_seen_at", "revoked_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Device timestamps must be timezone-aware")
        return value
