from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AIBrain"
    environment: str = "development"
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"
    mock_provider_enabled: bool = True
    provider_priorities: str = "mock:100"
    provider_timeout_seconds: float = 30.0
    provider_health_check_timeout_seconds: float = 5.0
    provider_max_attempts: int = 2
    fallback_enabled: bool = True
    mock_provider_simulate_failure: bool = False
    database_url: str = "sqlite:///:memory:"
    session_ttl_seconds: int = Field(default=86_400, gt=0)
    max_request_body_bytes: int = Field(default=1_048_576, gt=0)
    runner_evidence_max_request_body_bytes: int = Field(
        default=15_728_640, gt=0
    )
    ai_max_concurrent_requests: int = Field(default=10, gt=0)
    integration_vault_key_b64: SecretStr | None = Field(default=None, repr=False)
    provider_operator_token: SecretStr | None = Field(
        default=None,
        min_length=32,
    )
    trusted_runner_ingest_token: SecretStr | None = Field(
        default=None,
        min_length=32,
    )
    security_operator_emails: str = ""
    conformance_suite_authority_public_key_b64: str | None = None
    conformance_suite_authority_key_id: str | None = None
    conformance_suite_expected_id: str | None = None
    conformance_suite_expected_version: str | None = None
    login_rate_limit_attempts: int = Field(default=5, gt=0)
    login_rate_limit_window_seconds: int = Field(default=300, gt=0)
    security_recovery_abuse_backend: str = "sqlite"
    security_recovery_abuse_redis_url: SecretStr | None = Field(default=None, repr=False)
    security_recovery_abuse_hmac_key: SecretStr | None = Field(default=None, repr=False)
    security_recovery_abuse_redis_key_prefix: str = "aibrain:recovery-abuse:v1"
    security_recovery_abuse_redis_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    tool_execution_recovery_interval_seconds: int = Field(default=60, gt=0)
    tool_execution_stale_after_seconds: int = Field(default=300, gt=0)
    memory_retention_interval_seconds: int = Field(default=3_600, gt=0)
    integration_expiry_interval_seconds: int = Field(default=60, gt=0)
    integration_dispatch_recovery_interval_seconds: int = Field(default=60, gt=0)
    integration_dispatch_stale_after_seconds: int = Field(default=300, gt=0)
    security_notification_smtp_host: str | None = None
    security_notification_smtp_port: int = Field(default=587, ge=1, le=65535)
    security_notification_smtp_username: str | None = None
    security_notification_smtp_password: SecretStr | None = Field(default=None, repr=False)
    security_notification_sender: str | None = None
    security_notification_smtp_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    security_notification_worker_interval_seconds: int = Field(default=30, gt=0)
    security_notification_batch_size: int = Field(default=10, ge=1, le=100)

    webauthn_enabled: bool = False
    webauthn_rp_id: str | None = None
    webauthn_rp_name: str = "AIBrain"
    webauthn_allowed_origins: Annotated[tuple[str, ...], NoDecode] = ()
    webauthn_challenge_ttl_seconds: int = Field(default=300, gt=0)

    @model_validator(mode="after")
    def validate_security_recovery_abuse(self):
        backend = self.security_recovery_abuse_backend
        if backend not in {"sqlite", "redis"}:
            raise ValueError("Security recovery abuse backend must be sqlite or redis")
        redis_url = self.security_recovery_abuse_redis_url
        hmac_key = self.security_recovery_abuse_hmac_key
        if backend == "redis":
            if redis_url is None or hmac_key is None:
                raise ValueError("Redis recovery abuse protection requires a Redis URL and HMAC key")
            parsed = urlsplit(redis_url.get_secret_value())
            if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
                raise ValueError("Recovery abuse Redis URL must use redis:// or rediss://")
            if len(hmac_key.get_secret_value().encode("utf-8")) < 32:
                raise ValueError("Recovery abuse HMAC key must contain at least 32 bytes")
        if (
            not self.security_recovery_abuse_redis_key_prefix
            or len(self.security_recovery_abuse_redis_key_prefix) > 128
            or any(ch.isspace() for ch in self.security_recovery_abuse_redis_key_prefix)\n            or "{" in self.security_recovery_abuse_redis_key_prefix\n            or "}" in self.security_recovery_abuse_redis_key_prefix
        ):
            raise ValueError("Recovery abuse Redis key prefix is invalid")
        return self

    @model_validator(mode="after")
    def validate_security_notification_smtp(self):
        host = self.security_notification_smtp_host
        sender = self.security_notification_sender
        username = self.security_notification_smtp_username
        password = self.security_notification_smtp_password
        if bool(host) != bool(sender):
            raise ValueError("Security notification SMTP host and sender must be configured together")
        if bool(username) != bool(password):
            raise ValueError("Security notification SMTP username and password must be configured together")
        if username and not host:
            raise ValueError("SMTP credentials require security notification SMTP host and sender")
        for value in (host, sender, username):
            if value is not None and (not value.strip() or len(value) > 320 or chr(13) in value or chr(10) in value):
                raise ValueError("Security notification SMTP values must be valid single-line values")
        return self

    @property
    def security_notification_delivery_enabled(self) -> bool:
        return bool(self.security_notification_smtp_host and self.security_notification_sender)

    @model_validator(mode="after")
    def validate_integration_vault_key(self):
        if self.integration_vault_key_b64 is not None:
            import base64
            import binascii
            try:
                key = base64.b64decode(
                    self.integration_vault_key_b64.get_secret_value(),
                    validate=True,
                )
            except (ValueError, binascii.Error) as exc:
                raise ValueError("Integration vault key must be valid base64") from exc
            if len(key) != 32:
                raise ValueError("Integration vault key must decode to exactly 32 bytes")
        return self

    @model_validator(mode="after")
    def validate_privileged_tokens_are_separate(self):
        configured = [
            token.get_secret_value()
            for token in (
                self.provider_operator_token,
                self.trusted_runner_ingest_token,
            )
            if token is not None
        ]
        if len(configured) != len(set(configured)):
            raise ValueError(
                "Provider operator and runner ingestion tokens must be distinct"
            )
        return self

    @model_validator(mode="after")
    def validate_conformance_suite_authority(self):
        values = (
            self.conformance_suite_authority_public_key_b64,
            self.conformance_suite_authority_key_id,
            self.conformance_suite_expected_id,
            self.conformance_suite_expected_version,
        )
        if any(value is not None for value in values):
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError("All conformance suite authority pins must be configured together")
            import base64
            import binascii
            try:
                public_key = base64.b64decode(
                    self.conformance_suite_authority_public_key_b64,
                    validate=True,
                )
            except (ValueError, binascii.Error) as exc:
                raise ValueError("Conformance suite authority public key must be valid base64") from exc
            if len(public_key) != 32:
                raise ValueError("Conformance suite authority public key must decode to 32 bytes")
            for value in values[1:]:
                if len(value) > 256:
                    raise ValueError("Conformance suite authority pins must be at most 256 characters")
        return self

    @field_validator("webauthn_allowed_origins", mode="before")
    @classmethod
    def parse_webauthn_origins(cls, value):
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            return tuple(
                origin.strip()
                for origin in value.split(",")
                if origin.strip()
            )
        if isinstance(value, (list, tuple)):
            return tuple(value)
        raise ValueError("WebAuthn origins must be comma-separated")

    @field_validator("webauthn_rp_id")
    @classmethod
    def validate_webauthn_rp_id(cls, value):
        if value is None:
            return None

        value = value.strip().lower()
        if not value or value.endswith(".") or "/" in value or ":" in value:
            raise ValueError("Invalid WebAuthn RP ID")

        if value == "localhost":
            return value

        labels = value.split(".")
        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not label.replace("-", "").isalnum()
            or not label.isascii()
            for label in labels
        ):
            raise ValueError("Invalid WebAuthn RP ID")

        return value

    @field_validator("webauthn_rp_name")
    @classmethod
    def validate_webauthn_rp_name(cls, value):
        value = value.strip()
        if not value or len(value) > 64:
            raise ValueError("WebAuthn RP name must contain 1 to 64 characters")
        return value

    @model_validator(mode="after")
    def validate_webauthn_configuration(self):
        if self.webauthn_enabled and (
            self.webauthn_rp_id is None
            or not self.webauthn_allowed_origins
        ):
            raise ValueError(
                "Enabled WebAuthn requires an explicit RP ID and allowed origins"
            )

        if self.webauthn_allowed_origins and self.webauthn_rp_id is None:
            raise ValueError("WebAuthn origins require an explicit RP ID")

        seen = set()
        canonical_origins = []

        for origin in self.webauthn_allowed_origins:
            try:
                parsed = urlsplit(origin)
                hostname = parsed.hostname
                port = parsed.port
            except ValueError as exc:
                raise ValueError("Invalid WebAuthn origin") from exc

            if (
                not hostname
                or parsed.scheme not in ("https", "http")
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or origin != f"{parsed.scheme}://{parsed.netloc}"
                or parsed.netloc.endswith(":")
                or hostname.endswith(".")
            ):
                raise ValueError("Invalid WebAuthn origin")

            hostname = hostname.lower()

            expected_authority = hostname
            if port is not None:
                expected_authority += f":{port}"

            if parsed.netloc.lower() != expected_authority:
                raise ValueError("Invalid WebAuthn origin")

            is_localhost = (
                hostname == "localhost"
                and self.webauthn_rp_id == "localhost"
                and self.environment == "development"
            )

            if parsed.scheme != "https" and not is_localhost:
                raise ValueError(
                    "WebAuthn origins must use HTTPS except local development"
                )

            if hostname != self.webauthn_rp_id and not hostname.endswith(
                "." + (self.webauthn_rp_id or "")
            ):
                raise ValueError(
                    "WebAuthn origin hostname must match the RP ID or a subdomain"
                )

            normalized_port = port
            if (
                parsed.scheme == "https" and port == 443
            ) or (
                parsed.scheme == "http" and port == 80
            ):
                normalized_port = None

            normalized = f"{parsed.scheme}://{hostname}"
            if normalized_port is not None:
                normalized += f":{normalized_port}"

            if normalized in seen:
                raise ValueError("Duplicate WebAuthn origin")

            seen.add(normalized)
            canonical_origins.append(normalized)

        self.webauthn_allowed_origins = tuple(canonical_origins)
        return self

    model_config = SettingsConfigDict(
        env_prefix="AIBRAIN_",
        env_file=".env",
        extra="ignore",
    )


def get_settings() -> Settings:
    return Settings()
