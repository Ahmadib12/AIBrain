from backend.app.config import Settings


def test_default_configuration(monkeypatch) -> None:
    for name in (
        "AIBRAIN_APP_NAME",
        "AIBRAIN_ENVIRONMENT",
        "AIBRAIN_LOG_LEVEL",
        "AIBRAIN_API_V1_PREFIX",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = Settings()
    assert settings.app_name == "AIBrain"
    assert settings.environment == "development"
    assert settings.log_level == "INFO"
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.mock_provider_enabled is True
    assert settings.provider_priorities == "mock:100"
    assert settings.provider_timeout_seconds == 30.0
    assert settings.provider_health_check_timeout_seconds == 5.0
    assert settings.provider_max_attempts == 2
    assert settings.fallback_enabled is True
    assert settings.mock_provider_simulate_failure is False


def test_environment_configuration(monkeypatch) -> None:
    monkeypatch.setenv("AIBRAIN_APP_NAME", "Test Brain")
    monkeypatch.setenv("AIBRAIN_ENVIRONMENT", "test")
    monkeypatch.setenv("AIBRAIN_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("AIBRAIN_MOCK_PROVIDER_ENABLED", "false")
    monkeypatch.setenv("AIBRAIN_PROVIDER_TIMEOUT_SECONDS", "5.5")
    monkeypatch.setenv("AIBRAIN_PROVIDER_HEALTH_CHECK_TIMEOUT_SECONDS", "1.25")
    monkeypatch.setenv("AIBRAIN_PROVIDER_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("AIBRAIN_FALLBACK_ENABLED", "false")
    monkeypatch.setenv("AIBRAIN_MOCK_PROVIDER_SIMULATE_FAILURE", "true")

    settings = Settings()
    assert settings.app_name == "Test Brain"
    assert settings.environment == "test"
    assert settings.log_level == "DEBUG"
    assert settings.mock_provider_enabled is False
    assert settings.provider_timeout_seconds == 5.5
    assert settings.provider_health_check_timeout_seconds == 1.25
    assert settings.provider_max_attempts == 3
    assert settings.fallback_enabled is False
    assert settings.mock_provider_simulate_failure is True



def test_session_ttl_must_be_positive(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_SESSION_TTL_SECONDS", "0")
    with pytest.raises(ValidationError):
        Settings()

    monkeypatch.setenv("AIBRAIN_SESSION_TTL_SECONDS", "-1")
    with pytest.raises(ValidationError):
        Settings()


def test_session_ttl_accepts_positive_value(monkeypatch) -> None:
    monkeypatch.setenv("AIBRAIN_SESSION_TTL_SECONDS", "60")

    settings = Settings()

    assert settings.session_ttl_seconds == 60


def test_webauthn_is_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("AIBRAIN_WEBAUTHN_ENABLED", raising=False)
    monkeypatch.delenv("AIBRAIN_WEBAUTHN_RP_ID", raising=False)
    monkeypatch.delenv("AIBRAIN_WEBAUTHN_RP_NAME", raising=False)
    monkeypatch.delenv("AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("AIBRAIN_WEBAUTHN_CHALLENGE_TTL_SECONDS", raising=False)

    settings = Settings()

    assert settings.webauthn_enabled is False
    assert settings.webauthn_rp_id is None
    assert settings.webauthn_rp_name == "AIBrain"
    assert settings.webauthn_allowed_origins == ()
    assert settings.webauthn_challenge_ttl_seconds == 300


def test_webauthn_requires_explicit_rp_id_and_origins(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.delenv("AIBRAIN_WEBAUTHN_RP_ID", raising=False)
    monkeypatch.delenv("AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS", raising=False)

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_accepts_matching_https_origins(monkeypatch) -> None:
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_NAME", "AIBrain")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://example.com,https://app.example.com",
    )
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_CHALLENGE_TTL_SECONDS", "180")

    settings = Settings()

    assert settings.webauthn_enabled is True
    assert settings.webauthn_rp_id == "example.com"
    assert settings.webauthn_allowed_origins == (
        "https://example.com",
        "https://app.example.com",
    )
    assert settings.webauthn_challenge_ttl_seconds == 180


def test_webauthn_rejects_mismatched_or_malformed_origins(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://attacker.invalid",
    )

    with pytest.raises(ValidationError):
        Settings()

    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://example.com/untrusted-path",
    )

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_allows_localhost_http_only_for_localhost_rp(monkeypatch) -> None:
    monkeypatch.setenv("AIBRAIN_ENVIRONMENT", "development")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "http://localhost:3000",
    )

    settings = Settings()

    assert settings.webauthn_allowed_origins == ("http://localhost:3000",)


def test_webauthn_rejects_invalid_rp_id(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    for rp_id in (
        "",
        "example.com/",
        "example.com:443",
        "-invalid.example",
        "example..com",
        "example.com.",
        "münich.example",
    ):
        monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", rp_id)

        with pytest.raises(ValidationError):
            Settings()


def test_webauthn_rejects_duplicate_origins(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://example.com,https://example.com",
    )

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_rejects_http_origin_outside_local_development(
    monkeypatch,
) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_ENVIRONMENT", "production")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "localhost")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "http://localhost:3000",
    )

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_rejects_origin_with_credentials(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://user:password@example.com",
    )

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_challenge_ttl_must_be_positive(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_WEBAUTHN_CHALLENGE_TTL_SECONDS", "0")

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_rejects_case_insensitive_duplicate_origins(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://EXAMPLE.com,https://example.com",
    )

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_rejects_default_port_duplicate_origins(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://example.com,https://example.com:443",
    )

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_rejects_http_origin_with_non_localhost_rp(monkeypatch) -> None:
    import pytest
    from pydantic import ValidationError

    monkeypatch.setenv("AIBRAIN_ENVIRONMENT", "development")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "http://app.example.com",
    )

    with pytest.raises(ValidationError):
        Settings()


def test_webauthn_canonicalizes_allowed_origins(monkeypatch) -> None:
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_ENABLED", "true")
    monkeypatch.setenv("AIBRAIN_WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv(
        "AIBRAIN_WEBAUTHN_ALLOWED_ORIGINS",
        "https://EXAMPLE.com:443",
    )

    settings = Settings()

    assert settings.webauthn_allowed_origins == ("https://example.com",)
