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


class InvalidProviderRequestError(ProviderError):
    def __init__(self, provider_id: str, message: str) -> None:
        super().__init__(
            provider_id,
            "INVALID_PROVIDER_REQUEST",
            message,
            retryable=False,
        )


class AllProvidersFailedError(Exception):
    def __init__(self, failures: list[ProviderFailure]) -> None:
        super().__init__("All eligible providers failed")
        self.failures = failures


class DuplicateProviderError(ValueError):
    pass
