from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AIBrain"
    environment: str = "development"
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"
    mock_provider_enabled: bool = True
    provider_priorities: str = "mock:100"
    provider_timeout_seconds: float = 30.0
    provider_max_attempts: int = 2
    fallback_enabled: bool = True
    mock_provider_simulate_failure: bool = False

    model_config = SettingsConfigDict(
        env_prefix="AIBRAIN_",
        env_file=".env",
        extra="ignore",
    )
