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
    assert settings.provider_max_attempts == 2
    assert settings.fallback_enabled is True
    assert settings.mock_provider_simulate_failure is False


def test_environment_configuration(monkeypatch) -> None:
    monkeypatch.setenv("AIBRAIN_APP_NAME", "Test Brain")
    monkeypatch.setenv("AIBRAIN_ENVIRONMENT", "test")
    monkeypatch.setenv("AIBRAIN_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("AIBRAIN_MOCK_PROVIDER_ENABLED", "false")
    monkeypatch.setenv("AIBRAIN_PROVIDER_TIMEOUT_SECONDS", "5.5")
    monkeypatch.setenv("AIBRAIN_PROVIDER_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("AIBRAIN_FALLBACK_ENABLED", "false")
    monkeypatch.setenv("AIBRAIN_MOCK_PROVIDER_SIMULATE_FAILURE", "true")

    settings = Settings()
    assert settings.app_name == "Test Brain"
    assert settings.environment == "test"
    assert settings.log_level == "DEBUG"
    assert settings.mock_provider_enabled is False
    assert settings.provider_timeout_seconds == 5.5
    assert settings.provider_max_attempts == 3
    assert settings.fallback_enabled is False
    assert settings.mock_provider_simulate_failure is True
