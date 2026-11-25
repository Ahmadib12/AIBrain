from datetime import datetime, timezone
import base64
import hashlib
import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from backend.app.agli.contracts import (
    AudioEncoding,
    DataClassification,
    LanguageDetectionRequest,
    LanguageDetectionResult,
    ProcessingPreference,
    SpeechSessionRequest,
    SpeechSynthesisRequest,
    TranscriptSegment,
    TranslationRequest,
)
from backend.app.devices.contracts import (
    DeviceCapability,
    DeviceCapabilityReport,
    DevicePlatform,
    DeviceRegistrationRequest,
)
from backend.app.events.contracts import EventEnvelope, EventType
from backend.app.sync.contracts import (
    SyncEntityType,
    SyncOperation,
    SyncOperationKind,
)


def test_language_contracts_are_bounded_and_default_to_local_only():
    request = TranslationRequest(
        text="Hello",
        target_language="ar",
    )
    assert request.processing_preference == ProcessingPreference.LOCAL_ONLY
    assert request.data_classification == DataClassification.CONFIDENTIAL

    with pytest.raises(ValidationError):
        TranslationRequest(text="   ", target_language="ar")

    with pytest.raises(ValidationError):
        LanguageDetectionRequest(text="x" * 20_001)

    with pytest.raises(ValidationError):
        LanguageDetectionResult(
            language="not a language tag",
            confidence=0.8,
            engine_id="test",
            engine_version="1",
        )


def test_speech_contracts_keep_audio_out_of_json_and_validate_segments():
    request = SpeechSessionRequest(
        session_id=uuid4(),
        target_language="fr",
        encoding=AudioEncoding.OPUS,
        sample_rate_hz=48_000,
        channels=1,
    )
    assert request.processing_preference == ProcessingPreference.LOCAL_ONLY
    assert "consent" not in request.model_dump()

    synthesis = SpeechSynthesisRequest(
        text="Bonjour",
        language="fr",
        encoding=AudioEncoding.OPUS,
    )
    assert synthesis.voice_id is None

    with pytest.raises(ValidationError):
        TranscriptSegment(
            segment_id=uuid4(),
            start_ms=900,
            end_ms=800,
            text="invalid order",
            language="en",
            confidence=0.9,
            is_final=True,
        )


def test_device_capability_report_is_descriptive_and_timezone_aware():
    request = DeviceRegistrationRequest(
        platform=DevicePlatform.ANDROID,
        app_version="0.1.0",
        public_key_fingerprint="a" * 64,
    )
    assert request.platform == DevicePlatform.ANDROID

    report = DeviceCapabilityReport(
        capabilities=(DeviceCapability.MICROPHONE,),
        reported_at=datetime.now(timezone.utc),
    )
    assert report.capabilities == (DeviceCapability.MICROPHONE,)

    with pytest.raises(ValidationError):
        DeviceRegistrationRequest(
            platform=DevicePlatform.ANDROID,
            app_version="0.1.0",
            public_key_fingerprint="not-a-fingerprint",
        )

    with pytest.raises(ValidationError):
        DeviceCapabilityReport(
            capabilities=(),
            reported_at=datetime(2026, 1, 1),
        )


def test_event_envelope_requires_timezone_and_bounded_json_payload():
    event = EventEnvelope(
        event_id=uuid4(),
        session_id=uuid4(),
        event_type=EventType.TRANSCRIPT_PARTIAL,
        sequence=1,
        occurred_at=datetime.now(timezone.utc),
        payload={"text": "hello", "is_final": False},
    )
    assert event.schema_version == 1

    with pytest.raises(ValidationError):
        EventEnvelope(
            event_id=uuid4(),
            session_id=uuid4(),
            event_type=EventType.ERROR,
            sequence=1,
            occurred_at=datetime(2026, 1, 1),
        )

    with pytest.raises(ValidationError):
        EventEnvelope(
            event_id=uuid4(),
            session_id=uuid4(),
            event_type=EventType.ERROR,
            sequence=1,
            occurred_at=datetime.now(timezone.utc),
            payload={"large": "x" * 17_000},
        )


def _sync_operation(**overrides):
    ciphertext = b"opaque-encrypted-payload"
    values = {
        "operation_id": uuid4(),
        "entity_id": uuid4(),
        "entity_type": SyncEntityType.MEMORY,
        "operation": SyncOperationKind.UPSERT,
        "entity_version": 1,
        "schema_version": 1,
        "occurred_at": datetime.now(timezone.utc),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "key_reference": "device-key-v1",
    }
    values.update(overrides)
    return SyncOperation(**values)


def test_sync_upsert_requires_valid_opaque_ciphertext_and_digest():
    operation = _sync_operation()
    assert operation.operation == SyncOperationKind.UPSERT

    with pytest.raises(ValidationError):
        _sync_operation(ciphertext_sha256="0" * 64)

    with pytest.raises(ValidationError):
        _sync_operation(ciphertext_b64="not base64!")


def test_sync_delete_is_a_tombstone_without_payload():
    operation = _sync_operation(
        operation=SyncOperationKind.DELETE,
        ciphertext_b64=None,
        ciphertext_sha256=None,
        key_reference=None,
    )
    assert operation.operation == SyncOperationKind.DELETE

    with pytest.raises(ValidationError):
        _sync_operation(
            operation=SyncOperationKind.DELETE,
        )
