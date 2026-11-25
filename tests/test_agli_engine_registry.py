from collections.abc import AsyncIterator

import pytest

from backend.app.agli.contracts import (
    EngineCapabilityProfile,
    EngineCapabilityState,
    EngineExecutionLocation,
    LanguageDetectionRequest,
    LanguageDetectionResult,
    SpeechEngine,
    SpeechSessionRequest,
    SpeechSynthesisEngine,
    SpeechSynthesisRequest,
    TranslationEngine,
    TranslationRequest,
    TranslationResult,
)
from backend.app.agli.engine_registry import (
    DuplicateLanguageEngineError,
    LanguageEngineRegistry,
    UnsupportedLanguageEngineError,
)
from backend.app.agli.schemas import LanguageCapability


class FakeTranslationEngine:
    async def detect(self, request: LanguageDetectionRequest) -> LanguageDetectionResult:
        return LanguageDetectionResult(
            language="en", confidence=1.0, engine_id="fake", engine_version="1"
        )

    async def translate(self, request: TranslationRequest) -> TranslationResult:
        return TranslationResult(
            translated_text="hello",
            source_language=request.source_language or "fr",
            target_language=request.target_language,
            engine_id="fake",
            engine_version="1",
        )


class FakeSpeechEngine:
    async def _segments(self, request: SpeechSessionRequest) -> AsyncIterator:
        if False:
            yield None

    def recognize(self, request: SpeechSessionRequest):
        return self._segments(request)


class FakeSynthesisEngine:
    async def _chunks(self, request: SpeechSynthesisRequest) -> AsyncIterator[bytes]:
        yield b"audio"

    def synthesize(self, request: SpeechSynthesisRequest):
        return self._chunks(request)


def _profile(capability, *, engine_id="engine", version="1", state=EngineCapabilityState.IMPLEMENTED):
    return EngineCapabilityProfile(
        engine_id=engine_id,
        engine_version=version,
        capability=capability,
        state=state,
        execution_location=EngineExecutionLocation.LOCAL,
        supported_languages=("en", "fr"),
    )


def test_registry_registers_and_resolves_translation_capabilities():
    registry = LanguageEngineRegistry()
    engine = FakeTranslationEngine()
    profile = _profile(LanguageCapability.TEXT_TRANSLATION)

    registry.register(profile, engine)

    assert registry.get(LanguageCapability.TEXT_TRANSLATION, "engine") is engine
    assert registry.get_profile(LanguageCapability.TEXT_TRANSLATION, "engine") == profile
    assert registry.list_profiles() == (profile,)


def test_registry_rejects_duplicate_engine_capability_registration():
    registry = LanguageEngineRegistry()
    profile = _profile(LanguageCapability.TEXT_TRANSLATION)
    registry.register(profile, FakeTranslationEngine())

    with pytest.raises(DuplicateLanguageEngineError):
        registry.register(profile, FakeTranslationEngine())


def test_registry_rejects_engine_that_does_not_implement_declared_capability():
    registry = LanguageEngineRegistry()

    with pytest.raises(UnsupportedLanguageEngineError):
        registry.register(
            _profile(LanguageCapability.SPEECH_RECOGNITION),
            FakeTranslationEngine(),
        )


def test_registry_rejects_disabled_engine():
    registry = LanguageEngineRegistry()

    with pytest.raises(ValueError, match="Disabled"):
        registry.register(
            _profile(
                LanguageCapability.TEXT_TRANSLATION,
                state=EngineCapabilityState.DISABLED,
            ),
            FakeTranslationEngine(),
        )


def test_registry_keeps_one_version_per_engine_identity():
    registry = LanguageEngineRegistry()
    registry.register(
        _profile(LanguageCapability.TEXT_TRANSLATION, version="1"),
        FakeTranslationEngine(),
    )

    with pytest.raises(ValueError, match="multiple versions"):
        registry.register(
            _profile(
                LanguageCapability.LANGUAGE_DETECTION,
                version="2",
            ),
            FakeTranslationEngine(),
        )


def test_registry_does_not_treat_live_translation_as_a_single_engine():
    registry = LanguageEngineRegistry()

    with pytest.raises(UnsupportedLanguageEngineError):
        registry.register(
            _profile(LanguageCapability.LIVE_TRANSLATION),
            FakeTranslationEngine(),
        )


def test_registry_supports_speech_engine_contracts():
    registry = LanguageEngineRegistry()
    asr_profile = _profile(LanguageCapability.SPEECH_RECOGNITION, engine_id="asr")
    tts_profile = _profile(LanguageCapability.SPEECH_SYNTHESIS, engine_id="tts")
    asr = FakeSpeechEngine()
    tts = FakeSynthesisEngine()

    registry.register(asr_profile, asr)
    registry.register(tts_profile, tts)

    assert registry.get(LanguageCapability.SPEECH_RECOGNITION, "asr") is asr
    assert registry.get(LanguageCapability.SPEECH_SYNTHESIS, "tts") is tts
