import math

import pytest
from pydantic import ValidationError

from backend.app.intelligence.schemas import IntelligenceRequest


def make_request(metadata: dict) -> IntelligenceRequest:
    return IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}],
        metadata=metadata,
    )


def test_metadata_rejects_serialized_utf8_payload_over_4096_bytes() -> None:
    # Each "é" occupies two UTF-8 bytes but one Python character.
    with pytest.raises(ValidationError, match="Request metadata is too large"):
        make_request({"label": "é" * 2045})


def test_metadata_accepts_payload_within_serialized_utf8_limit() -> None:
    request = make_request({"label": "é" * 2000})

    assert request.metadata == {"label": "é" * 2000}


def test_metadata_rejects_non_finite_numbers() -> None:
    with pytest.raises(
        ValidationError,
        match="Request metadata must be valid JSON",
    ):
        make_request({"score": math.nan})


def test_metadata_still_rejects_sensitive_keys() -> None:
    with pytest.raises(
        ValidationError,
        match="Sensitive credentials cannot be provided in metadata",
    ):
        make_request({"api_key": "do-not-accept"})
