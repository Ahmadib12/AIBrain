"""Trusted, composition-owned registry for AGLI runtime engines.

Profiles are supplied by server composition, never by API clients. A profile's
state is descriptive metadata; VERIFIED means an evaluation identity is present,
not that this registry independently validates the evaluation evidence.
"""
from backend.app.agli.contracts import (
    EngineCapabilityProfile,
    EngineCapabilityState,
    SpeechEngine,
    SpeechSynthesisEngine,
    TranslationEngine,
)
from backend.app.agli.schemas import LanguageCapability


class DuplicateLanguageEngineError(ValueError):
    """Raised when an engine identity/capability is registered more than once."""


class UnsupportedLanguageEngineError(ValueError):
    """Raised when an engine does not implement the declared capability."""


class LanguageEngineRegistry:
    """In-memory registry populated only by trusted application composition."""

    def __init__(self) -> None:
        self._engines: dict[tuple[LanguageCapability, str], object] = {}
        self._profiles: dict[tuple[LanguageCapability, str], EngineCapabilityProfile] = {}
        self._versions: dict[str, str] = {}

    @staticmethod
    def _supports(capability: LanguageCapability, engine: object) -> bool:
        if capability in (
            LanguageCapability.LANGUAGE_DETECTION,
            LanguageCapability.TEXT_TRANSLATION,
        ):
            required = ("detect",) if capability == LanguageCapability.LANGUAGE_DETECTION else ("translate",)
        elif capability == LanguageCapability.SPEECH_RECOGNITION:
            required = ("recognize",)
        elif capability == LanguageCapability.SPEECH_SYNTHESIS:
            required = ("synthesize",)
        else:
            # LIVE_TRANSLATION is a composed pipeline, not a single-engine
            # interface. It cannot be registered until its orchestration
            # contract is implemented.
            return False
        return all(callable(getattr(engine, name, None)) for name in required)

    def register(self, profile: EngineCapabilityProfile, engine: object) -> None:
        if profile.state == EngineCapabilityState.DISABLED:
            raise ValueError("Disabled language engines cannot be registered")
        if not self._supports(profile.capability, engine):
            raise UnsupportedLanguageEngineError(
                f"Engine does not implement capability '{profile.capability.value}'"
            )

        key = (profile.capability, profile.engine_id)
        if key in self._engines:
            raise DuplicateLanguageEngineError(
                f"Engine '{profile.engine_id}' is already registered for "
                f"'{profile.capability.value}'"
            )
        existing_version = self._versions.get(profile.engine_id)
        if existing_version is not None and existing_version != profile.engine_version:
            raise ValueError("An engine ID cannot be registered with multiple versions")

        self._engines[key] = engine
        self._profiles[key] = profile
        self._versions[profile.engine_id] = profile.engine_version

    def get(
        self,
        capability: LanguageCapability,
        engine_id: str,
    ) -> object | None:
        return self._engines.get((capability, engine_id))

    def get_profile(
        self,
        capability: LanguageCapability,
        engine_id: str,
    ) -> EngineCapabilityProfile | None:
        return self._profiles.get((capability, engine_id))

    def list_profiles(self) -> tuple[EngineCapabilityProfile, ...]:
        return tuple(
            self._profiles[key]
            for key in sorted(self._profiles, key=lambda item: (item[0].value, item[1]))
        )
