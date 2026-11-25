import asyncio

import pytest

from backend.app.agli.contracts import (
    DataClassification,
    EngineCapabilityProfile,
    EngineCapabilityState,
    EngineExecutionLocation,
    LanguageDetectionRequest,
    LanguageDetectionResult,
    LanguagePair,
    ProcessingPreference,
    TranslationRequest,
    TranslationResult,
)
from backend.app.agli.engine_registry import LanguageEngineRegistry
from backend.app.agli.execution import (
    LanguageCapabilityUnavailableError,
    LanguageEngineExecutionError,
    LanguageEngineExecutor,
)
from backend.app.agli.schemas import LanguageCapability


class DetectionEngine:
    def __init__(self, engine_id="local-detector", version="1.0") -> None:
        self.engine_id = engine_id
        self.version = version

    async def detect(self, request):
        return LanguageDetectionResult(
            language="en",
            confidence=0.99,
            engine_id=self.engine_id,
            engine_version=self.version,
        )


class TranslationEngine:
    async def translate(self, request):
        return TranslationResult(
            translated_text="Bonjour",
            source_language="en",
            target_language="fr",
            confidence=0.98,
            engine_id="translator",
            engine_version="1.0",
        )


def profile(
    capability,
    *,
    engine_id,
    location=EngineExecutionLocation.LOCAL,
    state=EngineCapabilityState.AVAILABLE,
    pairs=(),
):
    return EngineCapabilityProfile(
        engine_id=engine_id,
        engine_version="1.0",
        capability=capability,
        state=state,
        execution_location=location,
        supported_languages=("en", "fr"),
        supported_language_pairs=pairs,
    )


def test_executor_runs_available_local_detection_engine():
    registry = LanguageEngineRegistry()
    registry.register(
        profile(LanguageCapability.LANGUAGE_DETECTION, engine_id="local-detector"),
        DetectionEngine(),
    )
    result = asyncio.run(
        LanguageEngineExecutor(registry).detect(
            LanguageDetectionRequest(text="hello")
        )
    )
    assert result.language == "en"
    assert result.engine_id == "local-detector"


def test_local_only_request_never_falls_back_to_cloud_engine():
    registry = LanguageEngineRegistry()
    registry.register(
        profile(
            LanguageCapability.LANGUAGE_DETECTION,
            engine_id="cloud-detector",
            location=EngineExecutionLocation.CLOUD,
        ),
        DetectionEngine("cloud-detector"),
    )
    with pytest.raises(LanguageCapabilityUnavailableError):
        asyncio.run(
            LanguageEngineExecutor(registry).detect(
                LanguageDetectionRequest(
                    text="hello",
                    processing_preference=ProcessingPreference.LOCAL_ONLY,
                    data_classification=DataClassification.PUBLIC,
                )
            )
        )


def test_confidential_request_rejects_cloud_even_when_cloud_allowed():
    registry = LanguageEngineRegistry()
    registry.register(
        profile(
            LanguageCapability.LANGUAGE_DETECTION,
            engine_id="cloud-detector",
            location=EngineExecutionLocation.CLOUD,
        ),
        DetectionEngine("cloud-detector"),
    )
    with pytest.raises(LanguageCapabilityUnavailableError):
        asyncio.run(
            LanguageEngineExecutor(registry).detect(
                LanguageDetectionRequest(
                    text="private text",
                    data_classification=DataClassification.CONFIDENTIAL,
                    processing_preference=ProcessingPreference.CLOUD_ALLOWED,
                )
            )
        )


def test_engine_cannot_spoof_its_registered_identity():
    registry = LanguageEngineRegistry()
    registry.register(
        profile(LanguageCapability.LANGUAGE_DETECTION, engine_id="trusted-detector"),
        DetectionEngine("different-engine"),
    )
    with pytest.raises(LanguageEngineExecutionError):
        asyncio.run(
            LanguageEngineExecutor(registry).detect(
                LanguageDetectionRequest(text="hello")
            )
        )


def test_translation_requires_a_declared_language_pair():
    registry = LanguageEngineRegistry()
    registry.register(
        profile(
            LanguageCapability.TEXT_TRANSLATION,
            engine_id="translator",
            pairs=(LanguagePair(source_language="en", target_language="fr"),),
        ),
        TranslationEngine(),
    )
    result = asyncio.run(
        LanguageEngineExecutor(registry).translate(
            TranslationRequest(
                text="Hello",
                source_language="en",
                target_language="fr",
            )
        )
    )
    assert result.translated_text == "Bonjour"

    with pytest.raises(LanguageCapabilityUnavailableError):
        asyncio.run(
            LanguageEngineExecutor(registry).translate(
                TranslationRequest(
                    text="Hello",
                    source_language="fr",
                    target_language="en",
                )
            )
        )


def test_registered_or_implemented_engine_is_not_executable():
    registry = LanguageEngineRegistry()
    registry.register(
        profile(
            LanguageCapability.LANGUAGE_DETECTION,
            engine_id="not-ready",
            state=EngineCapabilityState.IMPLEMENTED,
        ),
        DetectionEngine("not-ready"),
    )
    with pytest.raises(LanguageCapabilityUnavailableError):
        asyncio.run(
            LanguageEngineExecutor(registry).detect(
                LanguageDetectionRequest(text="hello")
            )
        )
