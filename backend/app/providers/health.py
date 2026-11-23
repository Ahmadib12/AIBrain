import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from backend.app.providers.errors import (
    ProviderHealthTimeoutError,
    ProviderHealthUnavailableError,
)
from backend.app.providers.schemas import ProviderAvailability, ProviderHealth


class ProviderHealthMonitor:
    def __init__(self) -> None:
        self._statuses: dict[str, ProviderHealth] = {}
        self._health_check_locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def record_success(
        self,
        provider_id: str,
        latency_ms: float | None = None,
    ) -> ProviderHealth:
        previous = self._statuses.get(provider_id)
        status = ProviderHealth(
            provider_id=provider_id,
            availability=ProviderAvailability.AVAILABLE,
            last_success_at=self._timestamp(),
            last_failure_at=previous.last_failure_at if previous else None,
            consecutive_failures=0,
            last_latency_ms=latency_ms,
        )
        self._statuses[provider_id] = status
        return status

    def record_failure(
        self,
        provider_id: str,
        latency_ms: float | None = None,
    ) -> ProviderHealth:
        previous = self._statuses.get(provider_id)
        status = ProviderHealth(
            provider_id=provider_id,
            availability=ProviderAvailability.UNAVAILABLE,
            last_success_at=previous.last_success_at if previous else None,
            last_failure_at=self._timestamp(),
            consecutive_failures=(previous.consecutive_failures + 1)
            if previous
            else 1,
            last_latency_ms=latency_ms,
        )
        self._statuses[provider_id] = status
        return status

    def get(self, provider_id: str) -> ProviderHealth:
        return self._statuses.get(
            provider_id,
            ProviderHealth(
                provider_id=provider_id,
                availability=ProviderAvailability.UNKNOWN,
            ),
        )

    def snapshot(self) -> tuple[ProviderHealth, ...]:
        return tuple(
            self._statuses[key]
            for key in sorted(self._statuses)
        )

    def is_available(self, provider_id: str) -> bool:
        status = self._statuses.get(provider_id)
        return status is None or status.availability != ProviderAvailability.UNAVAILABLE

    async def check_health(
        self,
        provider_id: str,
        health_check: Callable[[], Awaitable[ProviderHealth]],
        *,
        timeout_seconds: float,
    ) -> ProviderHealth:
        if timeout_seconds <= 0:
            raise ValueError("Health-check timeout must be positive")

        lock = self._health_check_locks.setdefault(
            provider_id,
            asyncio.Lock(),
        )
        async with lock:
            try:
                status = await asyncio.wait_for(
                    health_check(),
                    timeout=timeout_seconds,
                )
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                self.record_failure(provider_id)
                raise ProviderHealthTimeoutError(provider_id) from None
            except Exception:
                self.record_failure(provider_id)
                raise

            if status.provider_id != provider_id:
                self.record_failure(provider_id)
                raise ProviderHealthUnavailableError(provider_id)

            if status.availability == ProviderAvailability.AVAILABLE:
                return self.record_success(provider_id)

            self.record_failure(provider_id)
            raise ProviderHealthUnavailableError(provider_id)
