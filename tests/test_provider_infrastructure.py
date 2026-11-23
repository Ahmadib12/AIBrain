import asyncio

import pytest

from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
    OverallExecutionDeadlineError,
    ProviderHealthTimeoutError,
    ProviderUnavailableError,
)
from backend.app.providers.fallback import FallbackExecutor
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.interface import AIProvider
from backend.app.providers.mock import MockAIProvider
from backend.app.providers.registry import ProviderRegistry
from backend.app.providers.router import ModelRouter
from backend.app.providers.schemas import (
    ChatRequest,
    ChatResponse,
    ProviderAvailability,
    ProviderHealth,
)
from backend.app.intelligence.context import ExecutionState
from backend.app.providers.routing import SafeProviderFailureCategory


class FailingProvider(AIProvider):
    def __init__(self, provider_id: str = "fail", priority: int = 50) -> None:
        self._id = provider_id
        self._priority = priority

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return "Failing test provider"

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def enabled(self) -> bool:
        return True

    @property
    def models(self) -> tuple[str, ...]:
        return ("test-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation",)

    async def generate(self, request: ChatRequest) -> ChatResponse:
        raise ProviderUnavailableError(self.id, "simulated failure")

    async def health_check(self):
        return await MockAIProvider().health_check()


class SlowProvider(AIProvider):
    def __init__(self, provider_id: str = "slow", priority: int = 10) -> None:
        self._id = provider_id
        self._priority = priority

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return "Slow test provider"

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def enabled(self) -> bool:
        return True

    @property
    def models(self) -> tuple[str, ...]:
        return ("slow-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation",)

    async def generate(self, request: ChatRequest) -> ChatResponse:
        await asyncio.sleep(1)
        return ChatResponse(
            content="too late",
            provider_id=self.id,
            model_id=self.models[0],
            latency_ms=1000,
        )

    async def health_check(self):
        return await MockAIProvider().health_check()


class CancelledProvider(AIProvider):
    @property
    def id(self) -> str:
        return "cancelled"

    @property
    def name(self) -> str:
        return "Cancelled test provider"

    @property
    def priority(self) -> int:
        return 10

    @property
    def enabled(self) -> bool:
        return True

    @property
    def models(self) -> tuple[str, ...]:
        return ("cancel-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation",)

    async def generate(self, request: ChatRequest) -> ChatResponse:
        await asyncio.sleep(10)
        raise AssertionError("Cancelled call should not continue")

    async def health_check(self):
        return await MockAIProvider().health_check()


def chat_request(content: str = "Hello") -> ChatRequest:
    return ChatRequest(messages=[{"role": "user", "content": content}])


def build_router(*providers: AIProvider, max_attempts: int = 1,
                 timeout: float = 1.0, fallback_enabled: bool = True) -> ModelRouter:
    registry = ProviderRegistry()
    for provider in providers:
        registry.register(provider)
    monitor = ProviderHealthMonitor()
    executor = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=timeout,
        max_attempts=max_attempts,
    )
    return ModelRouter(
        registry,
        monitor,
        executor,
        fallback_enabled=fallback_enabled,
    )


@pytest.mark.asyncio
async def test_mock_provider_returns_deterministic_response() -> None:
    provider = MockAIProvider()

    response = await provider.generate(chat_request("Test message"))

    assert response.provider_id == "mock"
    assert response.model_id == "mock-chat-v1"
    assert response.content == "[mock response] Test message"
    assert response.metadata == {"deterministic": True}


@pytest.mark.asyncio
async def test_mock_provider_simulated_failure() -> None:
    provider = MockAIProvider(simulate_failure=True)

    with pytest.raises(ProviderUnavailableError) as error:
        await provider.generate(chat_request())

    assert error.value.provider_id == "mock"


@pytest.mark.asyncio
async def test_mock_provider_health_check() -> None:
    provider = MockAIProvider()
    health = await provider.health_check()

    assert health.provider_id == "mock"
    assert health.availability == ProviderAvailability.AVAILABLE


def test_provider_registration_and_duplicate_handling() -> None:
    registry = ProviderRegistry()
    registry.register(MockAIProvider())

    assert registry.get("mock") is not None
    assert registry.list()[0].id == "mock"
    with pytest.raises(ValueError, match="already registered"):
        registry.register(MockAIProvider())


def test_provider_discovery_retrieval_and_disablement() -> None:
    registry = ProviderRegistry()
    provider = MockAIProvider(enabled=False)
    registry.register(provider)

    assert registry.get("mock") is provider
    assert registry.enabled() == ()
    assert registry.get("missing") is None


@pytest.mark.asyncio
async def test_router_explicit_provider_selection() -> None:
    mock = MockAIProvider()
    router = build_router(mock)

    response = await router.route(
        ChatRequest(messages=[{"role": "user", "content": "Hi"}], provider="mock")
    )

    assert response.provider_id == "mock"


@pytest.mark.asyncio
async def test_router_unknown_explicit_provider() -> None:
    router = build_router(MockAIProvider())

    with pytest.raises(InvalidProviderRequestError) as error:
        await router.route(
            ChatRequest(
                messages=[{"role": "user", "content": "Hi"}],
                provider="missing",
            )
        )

    assert error.value.error_code == "INVALID_PROVIDER_REQUEST"


@pytest.mark.asyncio
async def test_router_falls_back_by_priority() -> None:
    failing = FailingProvider("fail", priority=100)
    mock = MockAIProvider(priority=50)
    router = build_router(failing, mock, max_attempts=1)

    response = await router.route(
        ChatRequest(
            messages=[{"role": "user", "content": "Hello"}],
            allow_fallback=True,
        )
    )

    assert response.provider_id == "mock"


@pytest.mark.asyncio
async def test_default_fallback_disabled_uses_only_top_provider() -> None:
    failing = FailingProvider("fail", priority=100)
    mock = MockAIProvider(priority=50)
    router = build_router(
        failing,
        mock,
        max_attempts=1,
        fallback_enabled=True,
    )

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route(chat_request())

    assert [failure.provider_id for failure in error.value.failures] == ["fail"]


@pytest.mark.asyncio
async def test_explicit_provider_fails_with_fallback_disabled() -> None:
    failing = FailingProvider("fail", priority=100)
    mock = MockAIProvider(priority=50)
    router = build_router(failing, mock, max_attempts=1)

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
                provider="fail",
                allow_fallback=False,
            )
        )

    assert [failure.provider_id for failure in error.value.failures] == ["fail"]


@pytest.mark.asyncio
async def test_global_fallback_disabled_ignores_request_fallback() -> None:
    failing = FailingProvider("fail", priority=100)
    mock = MockAIProvider(priority=50)
    router = build_router(
        failing,
        mock,
        max_attempts=1,
        fallback_enabled=False,
    )

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
                provider="fail",
                allow_fallback=True,
            )
        )

    assert [failure.provider_id for failure in error.value.failures] == ["fail"]


@pytest.mark.asyncio
async def test_explicit_provider_fails_with_fallback_enabled() -> None:
    failing = FailingProvider("fail", priority=100)
    mock = MockAIProvider(priority=50)
    router = build_router(failing, mock, max_attempts=1)

    response = await router.route(
        ChatRequest(
            messages=[{"role": "user", "content": "Hello"}],
            provider="fail",
            allow_fallback=True,
        )
    )

    assert response.provider_id == "mock"


@pytest.mark.asyncio
async def test_explicit_provider_success_ignores_alternative() -> None:
    mock = MockAIProvider(priority=100)
    failing = FailingProvider("fail", priority=50)
    router = build_router(mock, failing, max_attempts=1)

    response = await router.route(
        ChatRequest(
            messages=[{"role": "user", "content": "Hello"}],
            provider="mock",
            allow_fallback=True,
        )
    )

    assert response.provider_id == "mock"
    assert router.health_monitor.get("fail").availability == ProviderAvailability.UNKNOWN


@pytest.mark.asyncio
async def test_fallback_attempts_each_provider_only_once() -> None:
    failing = FailingProvider("fail", priority=100)
    mock = MockAIProvider(priority=50)

    monitor = ProviderHealthMonitor()
    executor = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=1,
        max_attempts=3,
    )

    response = await executor.execute(
        [failing, failing, mock],
        ChatRequest(messages=[{"role": "user", "content": "Hello"}]),
    )

    assert response.provider_id == "mock"


@pytest.mark.asyncio
async def test_all_providers_failed_returns_structured_error() -> None:
    router = build_router(FailingProvider(), max_attempts=1)

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route(chat_request())

    assert error.value.failures[0].provider_id == "fail"
    assert error.value.failures[0].error_code == "PROVIDER_UNAVAILABLE"


@pytest.mark.asyncio
async def test_retry_limit_is_bounded() -> None:
    provider = FailingProvider()
    monitor = ProviderHealthMonitor()
    executor = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=1,
        max_attempts=2,
    )

    with pytest.raises(AllProvidersFailedError) as error:
        await executor.execute([provider], chat_request())

    assert len(error.value.failures) == 2
    assert monitor.get("fail").consecutive_failures == 2


@pytest.mark.asyncio
async def test_provider_timeout() -> None:
    router = build_router(SlowProvider(), timeout=0.01)

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route(ChatRequest(
            messages=[{"role": "user", "content": "Hi"}],
            model="slow-chat-v1",
        ))

    assert error.value.failures[0].error_code == "PROVIDER_TIMEOUT"


@pytest.mark.asyncio
async def test_cancellation_is_not_swallowed() -> None:
    router = build_router(CancelledProvider(), timeout=1)
    task = asyncio.create_task(router.route(ChatRequest(
        messages=[{"role": "user", "content": "Hi"}],
        model="cancel-chat-v1",
    )))
    await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_health_monitor_tracks_success_and_failure() -> None:
    monitor = ProviderHealthMonitor()

    success = monitor.record_success("mock", latency_ms=12.5)
    failure = monitor.record_failure("mock", latency_ms=20)
    recovered = monitor.record_success("mock", latency_ms=10)

    assert success.availability == ProviderAvailability.AVAILABLE
    assert failure.availability == ProviderAvailability.UNAVAILABLE
    assert failure.consecutive_failures == 1
    assert recovered.consecutive_failures == 0
    assert monitor.get("mock").last_latency_ms == 10


@pytest.mark.asyncio
async def test_health_check_timeout_is_bounded_and_marks_unavailable() -> None:
    monitor = ProviderHealthMonitor()

    async def slow_health_check():
        await asyncio.sleep(1)
        return MockAIProvider().health_check()

    with pytest.raises(ProviderHealthTimeoutError):
        await monitor.check_health(
            "slow",
            slow_health_check,
            timeout_seconds=0.01,
        )

    status = monitor.get("slow")
    assert status.availability == ProviderAvailability.UNAVAILABLE
    assert status.consecutive_failures == 1


@pytest.mark.asyncio
async def test_health_check_cancellation_is_not_health_failure() -> None:
    monitor = ProviderHealthMonitor()

    async def cancelled_health_check():
        await asyncio.sleep(10)
        return await MockAIProvider().health_check()

    task = asyncio.create_task(
        monitor.check_health(
            "cancelled",
            cancelled_health_check,
            timeout_seconds=1,
        )
    )
    await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert monitor.get("cancelled").availability == ProviderAvailability.UNKNOWN


@pytest.mark.asyncio
async def test_concurrent_health_checks_preserve_explicit_state() -> None:
    monitor = ProviderHealthMonitor()

    async def healthy_health_check():
        await asyncio.sleep(0.01)
        return ProviderHealth(
            provider_id="shared",
            availability=ProviderAvailability.AVAILABLE,
        )

    first = asyncio.create_task(
        monitor.check_health(
            "shared",
            healthy_health_check,
            timeout_seconds=1,
        )
    )
    second = asyncio.create_task(
        monitor.check_health(
            "shared",
            healthy_health_check,
            timeout_seconds=1,
        )
    )
    statuses = await asyncio.gather(first, second)

    assert all(
        status.availability == ProviderAvailability.AVAILABLE
        for status in statuses
    )
    assert monitor.get("shared").consecutive_failures == 0


@pytest.mark.asyncio
async def test_health_check_success_recovers_failed_provider() -> None:
    monitor = ProviderHealthMonitor()
    monitor.record_failure("recover")

    async def healthy_health_check():
        return ProviderHealth(
            provider_id="recover",
            availability=ProviderAvailability.AVAILABLE,
        )

    status = await monitor.check_health(
        "recover",
        healthy_health_check,
        timeout_seconds=1,
    )

    assert status.availability == ProviderAvailability.AVAILABLE
    assert status.consecutive_failures == 0


@pytest.mark.asyncio
async def test_health_check_with_wrong_provider_identity_is_unavailable() -> None:
    from backend.app.providers.errors import ProviderHealthUnavailableError
    from backend.app.providers.schemas import ProviderHealth

    monitor = ProviderHealthMonitor()

    async def mismatched_health_check():
        return ProviderHealth(
            provider_id="different",
            availability=ProviderAvailability.AVAILABLE,
        )

    with pytest.raises(ProviderHealthUnavailableError):
        await monitor.check_health(
            "expected",
            mismatched_health_check,
            timeout_seconds=1,
        )

    assert monitor.get("expected").availability == ProviderAvailability.UNAVAILABLE


class SuccessProvider(AIProvider):
    def __init__(self, provider_id: str = "success", priority: int = 10) -> None:
        self._id = provider_id
        self._priority = priority

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return "Successful test provider"

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def enabled(self) -> bool:
        return True

    @property
    def models(self) -> tuple[str, ...]:
        return ("test-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation",)

    async def generate(self, request: ChatRequest) -> ChatResponse:
        return ChatResponse(
            content=f"success {request.messages[-1].content}",
            provider_id=self.id,
            model_id=self.models[0],
            latency_ms=1,
        )

    async def health_check(self):
        return await MockAIProvider().health_check()


class UnexpectedProvider(AIProvider):
    @property
    def id(self) -> str:
        return "unexpected"

    @property
    def name(self) -> str:
        return "Unexpected test provider"

    @property
    def priority(self) -> int:
        return 10

    @property
    def enabled(self) -> bool:
        return True

    @property
    def models(self) -> tuple[str, ...]:
        return ("test-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation",)

    async def generate(self, request: ChatRequest) -> ChatResponse:
        raise RuntimeError("sensitive unexpected provider detail")

    async def health_check(self):
        return await MockAIProvider().health_check()


class ProviderInvalidRequestProvider(AIProvider):
    def __init__(self, priority: int = 100) -> None:
        self._priority = priority

    @property
    def id(self) -> str:
        return "provider-invalid"

    @property
    def name(self) -> str:
        return "Invalid-request test provider"

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def enabled(self) -> bool:
        return True

    @property
    def models(self) -> tuple[str, ...]:
        return ("test-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation",)

    async def generate(self, request: ChatRequest) -> ChatResponse:
        raise InvalidProviderRequestError(
            self.id,
            "sensitive provider-side rejection",
            source="provider",
        )

    async def health_check(self):
        return await MockAIProvider().health_check()


@pytest.mark.asyncio
async def test_first_provider_timeout_then_success_outcome() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.01,
        max_attempts=1,
    )
    router = build_router(SlowProvider(priority=100), SuccessProvider(priority=50))

    registry = ProviderRegistry()
    registry.register(SlowProvider(priority=100))
    registry.register(SuccessProvider(priority=50))
    router = ModelRouter(
        registry,
        monitor,
        fallback,
        fallback_enabled=True,
    )
    loop = asyncio.get_running_loop()
    state = ExecutionState(
        deadline=loop.time() + 1,
        provider_attempt_timeout=0.01,
    )

    result = await router.route_with_outcome(
        ChatRequest(
            messages=[{"role": "user", "content": "Hello"}],
            allow_fallback=True,
        ),
        state,
    )

    assert result.response.provider_id == "success"
    assert result.summary.provider_attempt_count == 2
    assert result.summary.retry_count == 1
    assert result.summary.fallback_attempted is True
    assert result.summary.fallback_succeeded is True
    assert result.summary.intermediate_failure_categories == (
        SafeProviderFailureCategory.PROVIDER_TIMEOUT,
    )


@pytest.mark.asyncio
async def test_all_provider_timeouts_have_safe_outcome() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.01,
        max_attempts=1,
    )
    registry = ProviderRegistry()
    registry.register(SlowProvider("slow-a", priority=100))
    registry.register(SlowProvider("slow-b", priority=50))
    router = ModelRouter(registry, monitor, fallback, fallback_enabled=True)
    state = ExecutionState(
        deadline=asyncio.get_running_loop().time() + 1,
        provider_attempt_timeout=0.01,
    )

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route_with_outcome(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
                allow_fallback=True,
            ),
            state,
        )

    failures = error.value.failures
    assert failures
    assert {failure.error_code for failure in failures} == {"PROVIDER_TIMEOUT"}
    assert error.value.routing_summary is not None
    assert error.value.routing_summary.provider_attempt_count == 2


@pytest.mark.asyncio
async def test_mixed_provider_failures_are_aggregate() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.01,
        max_attempts=1,
    )
    registry = ProviderRegistry()
    registry.register(SlowProvider("slow", priority=100))
    registry.register(FailingProvider("unavailable", priority=50))
    router = ModelRouter(registry, monitor, fallback, fallback_enabled=True)
    state = ExecutionState(
        deadline=asyncio.get_running_loop().time() + 1,
        provider_attempt_timeout=0.01,
    )

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route_with_outcome(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
                allow_fallback=True,
            ),
            state,
        )

    assert {failure.error_code for failure in error.value.failures} == {
        "PROVIDER_TIMEOUT",
        "PROVIDER_UNAVAILABLE",
    }
    assert error.value.routing_summary is not None


@pytest.mark.asyncio
async def test_caller_invalid_provider_and_model_are_marked_caller() -> None:
    router = build_router(MockAIProvider())

    with pytest.raises(InvalidProviderRequestError) as unknown:
        await router.route(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
                provider="missing",
            )
        )
    assert unknown.value.source == "caller"

    with pytest.raises(InvalidProviderRequestError) as model:
        await router.route(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
                provider="mock",
                model="missing-model",
            )
        )
    assert model.value.source == "caller"


@pytest.mark.asyncio
async def test_provider_side_invalid_request_is_not_caller_invalid() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.1,
        max_attempts=1,
    )
    registry = ProviderRegistry()
    registry.register(ProviderInvalidRequestProvider())
    router = ModelRouter(registry, monitor, fallback)

    with pytest.raises(AllProvidersFailedError) as error:
        await router.route_with_outcome(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
            )
        )

    assert error.value.failures
    assert error.value.failures[0].error_code == "INVALID_PROVIDER_REQUEST"


@pytest.mark.asyncio
async def test_provider_side_invalid_request_then_successful_fallback() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.1,
        max_attempts=1,
    )
    registry = ProviderRegistry()
    registry.register(ProviderInvalidRequestProvider())
    registry.register(SuccessProvider(priority=50))
    router = ModelRouter(registry, monitor, fallback, fallback_enabled=True)

    result = await router.route_with_outcome(
        ChatRequest(
            messages=[{"role": "user", "content": "Hello"}],
            allow_fallback=True,
        )
    )

    assert result.response.provider_id == "success"
    assert result.summary.fallback_attempted is True
    assert result.summary.fallback_succeeded is True
    assert (
        SafeProviderFailureCategory.INVALID_PROVIDER_REQUEST
        in result.summary.intermediate_failure_categories
    )


@pytest.mark.asyncio
async def test_overall_deadline_during_retry_and_attempt_race() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.01,
        max_attempts=3,
    )
    state = ExecutionState(
        deadline=asyncio.get_running_loop().time() + 0.005,
        provider_attempt_timeout=0.01,
    )

    with pytest.raises(OverallExecutionDeadlineError):
        await fallback.execute_with_outcome(
            [SlowProvider()],
            ChatRequest(messages=[{"role": "user", "content": "Hello"}]),
            state,
        )


@pytest.mark.asyncio
async def test_overall_deadline_between_provider_attempts() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.01,
        max_attempts=1,
    )
    state = ExecutionState(
        deadline=asyncio.get_running_loop().time() + 0.005,
        provider_attempt_timeout=0.01,
    )

    with pytest.raises(OverallExecutionDeadlineError):
        await fallback.execute_with_outcome(
            [SlowProvider(priority=100), SuccessProvider(priority=50)],
            ChatRequest(messages=[{"role": "user", "content": "Hello"}]),
            state,
        )


@pytest.mark.asyncio
async def test_cancellation_during_attempt_and_fallback() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=1,
        max_attempts=1,
    )
    task = asyncio.create_task(
        fallback.execute_with_outcome(
            [CancelledProvider(), SuccessProvider()],
            ChatRequest(messages=[{"role": "user", "content": "Hello"}]),
        )
    )
    await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_concurrent_requests_have_independent_execution_states() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.02,
        max_attempts=1,
    )
    registry = ProviderRegistry()
    registry.register(SuccessProvider())
    router = ModelRouter(registry, monitor, fallback)
    loop = asyncio.get_running_loop()

    state_a = ExecutionState(
        deadline=loop.time() + 1,
        provider_attempt_timeout=0.02,
    )
    state_b = ExecutionState(
        deadline=loop.time() + 2,
        provider_attempt_timeout=0.02,
    )

    result_a, result_b = await asyncio.gather(
        router.route_with_outcome(
            ChatRequest(messages=[{"role": "user", "content": "A"}]),
            state_a,
        ),
        router.route_with_outcome(
            ChatRequest(messages=[{"role": "user", "content": "B"}]),
            state_b,
        ),
    )

    assert result_a.response.content == "success A"
    assert result_b.response.content == "success B"
    assert state_a.deadline != state_b.deadline


class EventProvider(AIProvider):
    def __init__(
        self,
        provider_id: str,
        *,
        priority: int,
        failure: Exception | None = None,
        success: bool = False,
        wait_forever: bool = False,
    ) -> None:
        self._id = provider_id
        self._priority = priority
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.failure = failure
        self.success = success
        self.wait_forever = wait_forever

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return f"Event {self._id}"

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def enabled(self) -> bool:
        return True

    @property
    def models(self) -> tuple[str, ...]:
        return ("test-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation",)

    async def generate(self, request: ChatRequest) -> ChatResponse:
        self.started.set()
        if self.wait_forever:
            await asyncio.Event().wait()
        await self.release.wait()
        if self.failure is not None:
            raise self.failure
        if self.success:
            return ChatResponse(
                content="event success",
                provider_id=self.id,
                model_id=self.models[0],
                latency_ms=1,
            )
        raise AssertionError("Event provider has no configured outcome")

    async def health_check(self):
        return await MockAIProvider().health_check()


@pytest.mark.asyncio
async def test_deadline_expires_before_second_provider_is_selected() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=1,
        max_attempts=1,
    )
    first = EventProvider(
        "first",
        priority=100,
        failure=ProviderUnavailableError(
            "first",
            "FIRST_PROVIDER_SENTINEL",
        ),
    )
    second = EventProvider(
        "second",
        priority=50,
        success=True,
    )
    loop = asyncio.get_running_loop()
    state = ExecutionState(
        deadline=loop.time() + 0.01,
        provider_attempt_timeout=1,
    )

    task = asyncio.create_task(
        fallback.execute_with_outcome(
            [first, second],
            ChatRequest(messages=[{"role": "user", "content": "Hello"}]),
            state,
        )
    )
    await first.started.wait()
    await asyncio.sleep(0.02)
    first.release.set()

    with pytest.raises(OverallExecutionDeadlineError):
        await task
    assert second.started.is_set() is False


@pytest.mark.asyncio
async def test_late_success_is_not_accepted_after_overall_deadline() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=1,
        max_attempts=1,
    )
    provider = EventProvider(
        "late",
        priority=100,
        success=True,
    )
    loop = asyncio.get_running_loop()
    state = ExecutionState(
        deadline=loop.time() + 0.01,
        provider_attempt_timeout=1,
    )

    task = asyncio.create_task(
        fallback.execute_with_outcome(
            [provider],
            ChatRequest(messages=[{"role": "user", "content": "Hello"}]),
            state,
        )
    )
    await provider.started.wait()
    await asyncio.sleep(0.02)
    provider.release.set()

    with pytest.raises(OverallExecutionDeadlineError):
        await task


@pytest.mark.asyncio
async def test_overall_deadline_wins_when_attempt_and_deadline_expire_together() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.01,
        max_attempts=1,
    )
    state = ExecutionState(
        deadline=asyncio.get_running_loop().time() + 0.01,
        provider_attempt_timeout=0.01,
    )

    with pytest.raises(OverallExecutionDeadlineError):
        await fallback.execute_with_outcome(
            [SlowProvider()],
            ChatRequest(messages=[{"role": "user", "content": "Hello"}]),
            state,
        )


@pytest.mark.asyncio
async def test_cancellation_during_second_fallback_provider() -> None:
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=1,
        max_attempts=1,
    )
    first = FailingProvider("first", priority=100)
    second = EventProvider(
        "second",
        priority=50,
        wait_forever=True,
        success=True,
    )
    registry = ProviderRegistry()
    registry.register(first)
    registry.register(second)
    router = ModelRouter(registry, monitor, fallback, fallback_enabled=True)

    task = asyncio.create_task(
        router.route_with_outcome(
            ChatRequest(
                messages=[{"role": "user", "content": "Hello"}],
                allow_fallback=True,
            )
        )
    )
    await second.started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
