"""Trusted, provider-neutral routing profiles and data-location policy."""
from __future__ import annotations

from enum import Enum
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from backend.app.providers.interface import AIProvider


class ProviderExecutionLocation(str, Enum):
    LOCAL = "local"
    CLOUD = "cloud"


class ProviderDataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"


class ProviderProfile(BaseModel):
    """Trusted deployment metadata; never accept this object from request JSON."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: str = Field(min_length=1, max_length=100)
    execution_location: ProviderExecutionLocation
    data_classifications: tuple[ProviderDataClass, ...] = Field(min_length=1, max_length=4)
    capabilities: tuple[str, ...] = Field(max_length=50)
    cost_tier: int = Field(ge=0, le=5)
    data_residency: str = Field(min_length=1, max_length=100)
    provider_version: str = Field(min_length=1, max_length=100)


class ProviderRoutingRequirements(BaseModel):
    """Trusted server-derived requirements for one provider selection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    data_classification: ProviderDataClass = ProviderDataClass.PUBLIC
    allowed_locations: tuple[ProviderExecutionLocation, ...] = Field(
        default=(ProviderExecutionLocation.LOCAL, ProviderExecutionLocation.CLOUD),
        min_length=1,
        max_length=2,
    )
    required_capabilities: tuple[str, ...] = Field(default=(), max_length=20)
    max_cost_tier: int = Field(default=5, ge=0, le=5)
    allowed_data_residencies: tuple[str, ...] = Field(default=(), max_length=10)


class ProviderProfileRegistry:
    """Composition-time registry; no public API registration is provided."""

    def __init__(self) -> None:
        self._profiles: dict[str, ProviderProfile] = {}

    def register(self, profile: ProviderProfile) -> None:
        if not isinstance(profile, ProviderProfile):
            raise TypeError("A validated trusted provider profile is required")
        if profile.provider_id in self._profiles:
            raise ValueError("Provider profile is already registered")
        self._profiles[profile.provider_id] = profile

    def get(self, provider_id: str) -> ProviderProfile | None:
        return self._profiles.get(provider_id)


class ProviderRoutingPolicy:
    def __init__(self, profiles: ProviderProfileRegistry) -> None:
        self.profiles = profiles

    def filter_candidates(
        self,
        candidates: Iterable[AIProvider],
        requirements: ProviderRoutingRequirements,
    ) -> tuple[AIProvider, ...]:
        if not isinstance(requirements, ProviderRoutingRequirements):
            raise TypeError("Trusted provider routing requirements are required")
        allowed: list[AIProvider] = []
        required_caps = set(requirements.required_capabilities)
        allowed_locations = set(requirements.allowed_locations)
        for provider in candidates:
            profile = self.profiles.get(provider.id)
            if profile is None:
                continue
            if profile.execution_location not in allowed_locations:
                continue
            if requirements.data_classification not in profile.data_classifications:
                continue
            if profile.cost_tier > requirements.max_cost_tier:
                continue
            if (
                requirements.allowed_data_residencies
                and profile.data_residency not in requirements.allowed_data_residencies
            ):
                continue
            if not required_caps.issubset(set(profile.capabilities)):
                continue
            if not required_caps.issubset(set(provider.capabilities)):
                continue
            allowed.append(provider)
        return tuple(allowed)
