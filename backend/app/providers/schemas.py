from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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
