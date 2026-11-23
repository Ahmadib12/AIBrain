import pytest
from backend.app.config import Settings


def test_provider_and_runner_privileged_tokens_must_be_distinct():
    shared = "shared-secret-value-" + "x" * 32
    with pytest.raises(ValueError, match="must be distinct"):
        Settings(
            provider_operator_token=shared,
            trusted_runner_ingest_token=shared,
        )


def test_security_operator_uses_account_allowlist_not_shared_secret():
    settings = Settings(
        provider_operator_token="provider-token-" + "p" * 32,
        trusted_runner_ingest_token="runner-token-" + "r" * 32,
        security_operator_emails="Security@example.com, reviewer@example.com",
    )
    assert settings.security_operator_emails == (
        "Security@example.com, reviewer@example.com"
    )
