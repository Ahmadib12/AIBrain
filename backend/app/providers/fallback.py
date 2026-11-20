import asyncio
import time
from collections.abc import Iterable

from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
    ProviderError,
    ProviderTimeoutError,
)
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.interface import AIProvider
from backend.app.providers.schemas import ChatRequest, ChatResponse


class FallbackExecutor:
    def __init__(
        self,
        *,
        health_monitor: ProviderHealthMonitor,
        timeout_seconds: float,
        max_attempts: int,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Provider timeout must be positive")
        if max_attempts < 1:
            raise ValueError("Provider max attempts must be at least one")
        self.health_monitor = health_monitor
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts

    async def execute(
        self,
        providers: Iterable[AIProvider],
        request: ChatRequest,
    ) -> ChatResponse:
        failures = []
        attempted_provider_ids: set[str] = set()

        for provider in providers:
            if provider.id in attempted_provider_ids:
                continue
            attempted_provider_ids.add(provider.id)
            for attempt in range(1, self.max_attempts + 1):
                started = time.perf_counter()
                try:
                    response = await asyncio.wait_for(
                        provider.generate(request),
                        timeout=self.timeout_seconds,
                    )
                    latency_ms = (time.perf_counter() - started) * 1000
                    self.health_monitor.record_success(
                        provider.id,
                        latency_ms=latency_ms,
                    )
                    return response
                except asyncio.CancelledError:
                    raise
                except asyncio.TimeoutError:
                    error = ProviderTimeoutError(provider.id)
                except InvalidProviderRequestError as error:
                    failures.append(error.as_failure())
                    break
                except ProviderError as provider_error:
                    error = provider_error
                    if not provider_error.retryable:
                        failures.append(provider_error.as_failure())
                        break
                except Exception as error:
                    error = ProviderError(
                        provider.id,
                        "PROVIDER_ERROR",
                        "Provider request failed",
                    )

                latency_ms = (time.perf_counter() - started) * 1000
                self.health_monitor.record_failure(provider.id, latency_ms)
                failures.append(error.as_failure())
                if attempt >= self.max_attempts:
                    break

        raise AllProvidersFailedError(failures)
