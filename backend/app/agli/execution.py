"""Fail-closed execution for trusted AGLI text engines.

Only composition-registered engines in AVAILABLE or VERIFIED state may run.
This module never performs provider discovery or cloud fallback.
"""
from backend.app.agli.contracts import (
    DataClassification,
    EngineCapabilityProfile,
    EngineCapabilityState,
    EngineExecutionLocation,
    LanguageDetectionRequest,
    LanguageDetectionResult,
    ProcessingPreference,
    TranslationRequest,
    TranslationResult,
)
from backend.app.agli.engine_registry import LanguageEngineRegistry
from backend.app.agli.schemas import LanguageCapability


class LanguageCapabilityUnavailableError(RuntimeError):
    """No trusted engine satisfies the request's declared policy."""


class LanguageEngineExecutionError(RuntimeError):
    """A registered engine failed its declared result contract."""


class LanguageEngineExecutor:
    """Select and execute one trusted engine without unsafe policy fallback."""

    _RUNTIME_STATES = {
        EngineCapabilityState.AVAILABLE,
        EngineCapabilityState.VERIFIED,
    }

    def __init__(self, registry: LanguageEngineRegistry) -> None:
        self._registry = registry

    @staticmethod
    def _allowed_locations(
        preference: ProcessingPreference,
        classification: DataClassification,
    ) -> tuple[EngineExecutionLocation, ...]:
        # Confidential and sensitive content never leaves the local boundary.
        if classification in {
            DataClassification.CONFIDENTIAL,
            DataClassification.SENSITIVE,
        }:
            return (EngineExecutionLocation.LOCAL,)
        if preference in {
            ProcessingPreference.LOCAL_ONLY,
            ProcessingPreference.LOCAL_PREFERRED,
        }:
            # LOCAL_PREFERRED deliberately does not silently authorize cloud
            # fallback. A future policy service may add an explicit fallback
            # decision backed by account consent and provider trust.
            return (EngineExecutionLocation.LOCAL,)
        return (
            EngineExecutionLocation.LOCAL,
            EngineExecutionLocation.CLOUD,
        )

    def _select(
        self,
        capability: LanguageCapability,
        *,
        preference: ProcessingPreference,
        classification: DataClassification,
        source_language: str | None = None,
        target_language: str | None = None,
    ) -> tuple[EngineCapabilityProfile, object]:
        allowed = self._allowed_locations(preference, classification)
        candidates: list[tuple[EngineCapabilityProfile, object]] = []
        for profile in self._registry.list_profiles():
            if profile.capability != capability or profile.state not in self._RUNTIME_STATES:
                continue
            if profile.execution_location not in allowed:
                continue
            languages = set(profile.supported_languages)
            if capability == LanguageCapability.LANGUAGE_DETECTION and not languages:
                continue
            if source_language is not None and source_language.lower() not in languages:
                if not any(
                    pair.source_language.lower() == source_language.lower()
                    and pair.target_language.lower() == (target_language or "").lower()
                    for pair in profile.supported_language_pairs
                ):
                    continue
            if target_language is not None:
                if profile.supported_language_pairs:
                    if not any(
                        pair.target_language.lower() == target_language.lower()
                        and (
                            source_language is None
                            or pair.source_language.lower() == source_language.lower()
                        )
                        for pair in profile.supported_language_pairs
                    ):
                        continue
                elif target_language.lower() not in languages:
                    continue
            engine = self._registry.get(capability, profile.engine_id)
            if engine is not None:
                candidates.append((profile, engine))

        if not candidates:
            raise LanguageCapabilityUnavailableError(
                "No available trusted engine satisfies the language and data policy"
            )
        # Local engines are preferred whenever both locations are explicitly
        # allowed. Stable ordering avoids nondeterministic routing.
        candidates.sort(
            key=lambda item: (
                item[0].execution_location != EngineExecutionLocation.LOCAL,
                item[0].engine_id,
            )
        )
        return candidates[0]

    @staticmethod
    def _validate_engine_identity(result, profile: EngineCapabilityProfile, expected_type):
        if not isinstance(result, expected_type):
            raise LanguageEngineExecutionError("Engine returned an invalid result type")
        if (
            result.engine_id != profile.engine_id
            or result.engine_version != profile.engine_version
        ):
            raise LanguageEngineExecutionError(
                "Engine result identity does not match its trusted profile"
            )
        return result

    async def detect(self, request: LanguageDetectionRequest) -> LanguageDetectionResult:
        profile, engine = self._select(
            LanguageCapability.LANGUAGE_DETECTION,
            preference=request.processing_preference,
            classification=request.data_classification,
        )
        try:
            result = await engine.detect(request)
        except Exception as error:
            raise LanguageEngineExecutionError("Language detection failed") from error
        return self._validate_engine_identity(
            result, profile, LanguageDetectionResult
        )

    async def translate(self, request: TranslationRequest) -> TranslationResult:
        profile, engine = self._select(
            LanguageCapability.TEXT_TRANSLATION,
            preference=request.processing_preference,
            classification=request.data_classification,
            source_language=request.source_language,
            target_language=request.target_language,
        )
        try:
            result = await engine.translate(request)
        except Exception as error:
            raise LanguageEngineExecutionError("Text translation failed") from error
        result = self._validate_engine_identity(
            result, profile, TranslationResult
        )
        if (
            result.source_language.lower()
            != (request.source_language or result.source_language).lower()
            or result.target_language.lower() != request.target_language.lower()
        ):
            raise LanguageEngineExecutionError(
                "Engine result language pair does not match the request"
            )
        return result
