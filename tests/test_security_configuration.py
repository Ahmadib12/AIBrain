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



def test_conformance_suite_authority_pins_must_be_configured_together():
    with pytest.raises(ValueError, match="configured together"):
        Settings(
            conformance_suite_authority_key_id="suite-authority",
        )


def test_conformance_suite_authority_requires_raw_ed25519_public_key():
    import base64

    with pytest.raises(ValueError, match="32 bytes"):
        Settings(
            conformance_suite_authority_public_key_b64=base64.b64encode(b"short").decode(),
            conformance_suite_authority_key_id="suite-authority",
            conformance_suite_expected_id="provider-suite",
            conformance_suite_expected_version="v1",
        )


def test_conformance_suite_authority_accepts_complete_deployment_pins():
    import base64

    settings = Settings(
        conformance_suite_authority_public_key_b64=base64.b64encode(b"k" * 32).decode(),
        conformance_suite_authority_key_id="suite-authority",
        conformance_suite_expected_id="provider-suite",
        conformance_suite_expected_version="v1",
    )
    assert settings.conformance_suite_authority_key_id == "suite-authority"
