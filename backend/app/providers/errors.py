from backend.app.providers.schemas import ProviderFailure


class ProviderError(Exception):
    def __init__(
        self,
        provider_id: str,
        error_code: str,
        message: str,
        *,
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.provider_id = provider_id
        self.error_code = error_code
        self.message = message
        self.retryable = retryable

    def as_failure(self) -> ProviderFailure:
        return ProviderFailure(
            provider_id=self.provider_id,
            error_code=self.error_code,
            message=self.message,
        )


class ProviderUnavailableError(ProviderError):
    def __init__(self, provider_id: str, message: str = "Provider unavailable") -> None:
        super().__init__(provider_id, "PROVIDER_UNAVAILABLE", message)


class ProviderTimeoutError(ProviderError):
    def __init__(self, provider_id: str) -> None:
        super().__init__(provider_id, "PROVIDER_TIMEOUT", "Provider request timed out")


class ProviderHealthTimeoutError(ProviderError):
    def __init__(self, provider_id: str) -> None:
        super().__init__(
            provider_id,
            "PROVIDER_HEALTH_TIMEOUT",
            "Provider health check timed out",
            retryable=False,
        )


class ProviderHealthUnavailableError(ProviderError):
    def __init__(self, provider_id: str) -> None:
        super().__init__(
            provider_id,
            "PROVIDER_HEALTH_UNAVAILABLE",
            "Provider health check reported unavailable",
            retryable=False,
        )


class InvalidProviderRequestError(ProviderError):
    def __init__(
        self,
        provider_id: str,
        message: str,
        *,
        source: str = "provider",
    ) -> None:
        super().__init__(
            provider_id,
            "INVALID_PROVIDER_REQUEST",
            message,
            retryable=False,
        )
        if source not in {"caller", "provider"}:
            raise ValueError("Invalid provider-request source")
        self.source = source


class OverallExecutionDeadlineError(Exception):
    def __init__(self, routing_summary=None) -> None:
        super().__init__("The overall execution deadline was exhausted")
        self.routing_summary = routing_summary


class AllProvidersFailedError(Exception):
    def __init__(
        self,
        failures: list[ProviderFailure],
        *,
        routing_summary=None,
        execution_deadline_exhausted: bool = False,
    ) -> None:
        super().__init__("All eligible providers failed")
        self.failures = failures
        self.routing_summary = routing_summary
        self.execution_deadline_exhausted = execution_deadline_exhausted


class DuplicateProviderError(ValueError):
    pass
