import pytest
from backend.app.config import Settings


def test_privileged_tokens_must_be_distinct():
    shared = "shared-secret-value-" + "x" * 32
    with pytest.raises(ValueError, match="must be distinct"):
        Settings(
            provider_operator_token=shared,
            trusted_runner_ingest_token=shared,
            security_operator_token="security-token-" + "s" * 32,
        )


def test_distinct_privileged_tokens_are_accepted():
    settings = Settings(
        provider_operator_token="provider-token-" + "p" * 32,
        trusted_runner_ingest_token="runner-token-" + "r" * 32,
        security_operator_token="security-token-" + "s" * 32,
    )
    assert settings.provider_operator_token is not None
    assert settings.trusted_runner_ingest_token is not None
    assert settings.security_operator_token is not None
    assert settings.provider_operator_token != settings.trusted_runner_ingest_token
    assert settings.provider_operator_token != settings.security_operator_token
    assert settings.trusted_runner_ingest_token != settings.security_operator_token
