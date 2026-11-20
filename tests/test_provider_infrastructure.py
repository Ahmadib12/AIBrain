import asyncio

import pytest

from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
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
)


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
    @property
    def id(self) -> str:
        return "slow"

    @property
    def name(self) -> str:
        return "Slow test provider"

    @property
    def priority(self) -> int:
        return 10

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
