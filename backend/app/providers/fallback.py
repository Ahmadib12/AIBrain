import asyncio
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING

from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
    OverallExecutionDeadlineError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.interface import AIProvider
from backend.app.providers.schemas import ChatRequest, ChatResponse
from backend.app.providers.routing import (
    ProviderRoutingResult,
    ProviderRoutingSummary,
    SafeProviderFailureCategory,
)

if TYPE_CHECKING:
    from backend.app.intelligence.context import ExecutionState


def _task_is_cancelled() -> bool:
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


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
        result = await self.execute_with_outcome(providers, request)
        return result.response

    async def execute_with_outcome(
        self,
        providers: Iterable[AIProvider],
        request: ChatRequest,
        execution_state: "ExecutionState | None" = None,
    ) -> ProviderRoutingResult:
        loop = asyncio.get_running_loop()
        provider_list = tuple(providers)

        if execution_state is None:
            from backend.app.intelligence.context import ExecutionState
            execution_state = ExecutionState(
                deadline=loop.time()
                + self.timeout_seconds
                * self.max_attempts
                * max(1, len(provider_list)),
                provider_attempt_timeout=self.timeout_seconds,
                overall_deadline_enabled=False,
            )

        failures = []
        categories: list[SafeProviderFailureCategory] = []
        provider_attempt_count = 0
        fallback_attempted = False
        fallback_succeeded = False
        attempted_provider_ids: set[str] = set()
        first_provider_id: str | None = None

        def deadline_error() -> OverallExecutionDeadlineError:
            summary = ProviderRoutingSummary(
                provider_attempt_count=provider_attempt_count,
                retry_count=max(0, provider_attempt_count - 1),
                fallback_attempted=fallback_attempted,
                fallback_succeeded=fallback_succeeded,
                intermediate_failure_categories=tuple(categories),
            )
            return OverallExecutionDeadlineError(summary)

        for provider in provider_list:
            if provider.id in attempted_provider_ids:
                continue
            attempted_provider_ids.add(provider.id)
            if first_provider_id is None:
                first_provider_id = provider.id

            for attempt in range(1, self.max_attempts + 1):
                if _task_is_cancelled():
                    raise asyncio.CancelledError()
                if execution_state.is_expired(loop):
                    raise deadline_error()

                started = time.perf_counter()
                remaining_budget = execution_state.remaining_budget(loop)
                attempt_timeout = min(
                    (
                        execution_state.provider_attempt_timeout
                        if execution_state.provider_attempt_timeout is not None
                        else self.timeout_seconds
                    ),
                    remaining_budget,
                )
                if attempt_timeout <= 0:
                    raise deadline_error()

                provider_attempt_count += 1
                if provider.id != first_provider_id:
                    fallback_attempted = True

                try:
                    response = await asyncio.wait_for(
                        provider.generate(request),
                        timeout=attempt_timeout,
                    )

                    if _task_is_cancelled():
                        raise asyncio.CancelledError()
                    if execution_state.is_expired(loop):
                        raise deadline_error()

                    latency_ms = (time.perf_counter() - started) * 1000
                    self.health_monitor.record_success(
                        provider.id,
                        latency_ms=latency_ms,
                    )
                    summary = ProviderRoutingSummary(
                        provider_attempt_count=provider_attempt_count,
                        retry_count=provider_attempt_count - 1,
                        fallback_attempted=fallback_attempted,
                        fallback_succeeded=fallback_attempted,
                        intermediate_failure_categories=tuple(categories),
                    )
                    return ProviderRoutingResult(
                        response=response,
                        summary=summary,
                    )
                except asyncio.CancelledError:
                    raise
                except asyncio.TimeoutError:
                    if _task_is_cancelled():
                        raise asyncio.CancelledError()
                    if execution_state.is_expired(loop):
                        raise deadline_error()
                    normalized_error = ProviderTimeoutError(provider.id)
                except InvalidProviderRequestError as error:
                    if _task_is_cancelled():
                        raise asyncio.CancelledError()
                    if execution_state.is_expired(loop):
                        raise deadline_error()
                    failures.append(error.as_failure())
                    categories.append(SafeProviderFailureCategory.INVALID_PROVIDER_REQUEST)
                    break
                except ProviderError as provider_error:
                    if _task_is_cancelled():
                        raise asyncio.CancelledError()
                    if execution_state.is_expired(loop):
                        raise deadline_error()
                    normalized_error = provider_error
                    if not provider_error.retryable:
                        failures.append(provider_error.as_failure())
                        category = (
                            SafeProviderFailureCategory.PROVIDER_UNAVAILABLE
                            if provider_error.error_code == "PROVIDER_UNAVAILABLE"
                            else SafeProviderFailureCategory.PROVIDER_FAILURE
                        )
                        categories.append(category)
                        break
                except Exception:
                    if _task_is_cancelled():
                        raise asyncio.CancelledError()
                    if execution_state.is_expired(loop):
                        raise deadline_error()
                    normalized_error = ProviderError(
                        provider.id,
                        "PROVIDER_ERROR",
                        "Provider request failed",
                    )

                if _task_is_cancelled():
                    raise asyncio.CancelledError()
                if execution_state.is_expired(loop):
                    raise deadline_error()

                latency_ms = (time.perf_counter() - started) * 1000
                self.health_monitor.record_failure(provider.id, latency_ms)
                failures.append(normalized_error.as_failure())
                if isinstance(normalized_error, ProviderTimeoutError):
                    categories.append(SafeProviderFailureCategory.PROVIDER_TIMEOUT)
                elif isinstance(normalized_error, ProviderUnavailableError):
                    categories.append(SafeProviderFailureCategory.PROVIDER_UNAVAILABLE)
                elif isinstance(normalized_error, ProviderError):
                    categories.append(SafeProviderFailureCategory.PROVIDER_FAILURE)
                if attempt >= self.max_attempts:
                    break

        summary = ProviderRoutingSummary(
            provider_attempt_count=provider_attempt_count,
            retry_count=max(0, provider_attempt_count - 1),
            fallback_attempted=fallback_attempted,
            fallback_succeeded=fallback_succeeded,
            intermediate_failure_categories=tuple(categories),
        )
        raise AllProvidersFailedError(failures, routing_summary=summary)
