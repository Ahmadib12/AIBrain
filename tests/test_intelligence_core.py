import asyncio
from copy import deepcopy

import pytest

from backend.app.intelligence.adapters import (
    AGLILanguageAdapter,
    AdapterFailureError,
    AdapterResult,
    CapabilityAdapter,
    InvalidAdapterResultError,
    ProviderRoutingAdapter,
)
from backend.app.intelligence.core import (
    CentralIntelligenceCore,
    OrchestrationCore,
)
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.schemas import (
    IntelligenceRequest,
    IntelligenceResponse,
    ResponseStatus,
    TaskType,
)
from backend.app.agli.core import AGLI
from backend.app.agli.registry import language_registry
from backend.app.providers.fallback import FallbackExecutor
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.mock import MockAIProvider
from backend.app.providers.registry import ProviderRegistry
from backend.app.providers.router import ModelRouter


class StubCentralIntelligenceCore(CentralIntelligenceCore):
    async def process(
        self,
        request: IntelligenceRequest,
    ) -> IntelligenceResponse:
        return IntelligenceResponse(
            task_type=TaskType.UNSUPPORTED,
            status=ResponseStatus.UNSUPPORTED,
            content="Core orchestration not implemented",
            warnings=("Phase 3A interface only",),
        )


@pytest.mark.asyncio
async def test_core_interface_can_be_implemented_by_a_stub() -> None:
    core = StubCentralIntelligenceCore()
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Test"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.UNSUPPORTED
    assert response.task_type == TaskType.UNSUPPORTED


def test_core_interface_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError):
        CentralIntelligenceCore()


class SuccessfulProviderAdapter(CapabilityAdapter):
    async def execute(self, request, context: RequestContext) -> AdapterResult:
        return AdapterResult(
            content="[mock provider] Hello",
            provider_id="mock",
            model_id="mock-chat-v1",
        )


class SuccessfulAGLIAdapter(CapabilityAdapter):
    async def execute(self, request, context: RequestContext) -> AdapterResult:
        return AdapterResult(
            content="English (en)",
            metadata={"native_name": "English"},
        )


class FailingAdapter(CapabilityAdapter):
    async def execute(self, request, context: RequestContext) -> AdapterResult:
        raise AdapterFailureError("Provider mock failure")


class InvalidResultAdapter(CapabilityAdapter):
    async def execute(self, request, context: RequestContext):
        return {"content": ""}


class CancellingAdapter(CapabilityAdapter):
    async def execute(self, request, context: RequestContext) -> AdapterResult:
        raise asyncio.CancelledError()


class TimeoutAdapter(CapabilityAdapter):
    async def execute(self, request, context: RequestContext) -> AdapterResult:
        await asyncio.sleep(1)
        return AdapterResult(content="too late")


class CapturingProviderAdapter(CapabilityAdapter):
    def __init__(self) -> None:
        self.context_ids: list[str] = []

    async def execute(self, request, context: RequestContext) -> AdapterResult:
        self.context_ids.append(context.context_id)
        return AdapterResult(content="captured")


class MetadataAdapter(CapabilityAdapter):
    def __init__(self, metadata: dict) -> None:
        self.metadata = metadata
        self.original_metadata = deepcopy(metadata)

    async def execute(self, request, context: RequestContext) -> AdapterResult:
        return AdapterResult(
            content="metadata test",
            metadata=self.metadata,
            provider_id="mock",
            model_id="mock-chat-v1",
        )


@pytest.mark.asyncio
async def test_successful_provider_delegation() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": SuccessfulProviderAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.COMPLETED
    assert response.content == "[mock provider] Hello"
    assert response.selected_capabilities == ("text_generation",)
    assert response.metadata["provider_id"] == "mock"
    assert response.metadata["model_id"] == "mock-chat-v1"


@pytest.mark.asyncio
async def test_successful_agli_delegation() -> None:
    core = OrchestrationCore(
        adapters={"language_lookup": SuccessfulAGLIAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Lookup language"}],
        task_type="language_lookup",
        language_code="en",
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.COMPLETED
    assert response.content == "English (en)"
    assert response.selected_capabilities == ("language_lookup",)


@pytest.mark.asyncio
async def test_provider_routing_adapter_delegates_to_existing_router() -> None:
    registry = ProviderRegistry()
    registry.register(MockAIProvider())
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=1,
        max_attempts=1,
    )
    router = ModelRouter(registry, monitor, fallback)
    core = OrchestrationCore(
        adapters={"text_generation": ProviderRoutingAdapter(router)}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.COMPLETED
    assert response.content == "[mock response] Hello"
    assert response.metadata["provider_id"] == "mock"


@pytest.mark.asyncio
async def test_agli_adapter_delegates_to_existing_registry() -> None:
    core = OrchestrationCore(
        adapters={"language_lookup": AGLILanguageAdapter(AGLI(language_registry))}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Lookup English"}],
        task_type="language_lookup",
        language_code="en",
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.COMPLETED
    assert response.content == "English (en)"
    assert response.metadata["native_name"] == "English"


@pytest.mark.asyncio
async def test_unsupported_task_has_controlled_response() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": SuccessfulProviderAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Send an email"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.UNSUPPORTED
    assert response.error_code == "UNSUPPORTED_TASK"
    assert response.content is None


@pytest.mark.asyncio
async def test_unavailable_capability_is_not_executed() -> None:
    core = OrchestrationCore()
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.ERROR
    assert response.error_code == "CAPABILITY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_adapter_failure_is_sanitized() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": FailingAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.ERROR
    assert response.error_code == "ADAPTER_FAILURE"
    assert "mock failure" not in str(response.model_dump())


@pytest.mark.asyncio
async def test_invalid_adapter_result_is_controlled() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": InvalidResultAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.ERROR
    assert response.error_code == "INVALID_ADAPTER_RESULT"


@pytest.mark.asyncio
async def test_adapter_cancellation_is_propagated() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": CancellingAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    with pytest.raises(asyncio.CancelledError):
        await core.process(request)


@pytest.mark.asyncio
async def test_core_context_isolation() -> None:
    adapter = CapturingProviderAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})
    first = IntelligenceRequest(
        messages=[{"role": "user", "content": "First"}],
        context_id="first-context",
    )
    second = IntelligenceRequest(
        messages=[{"role": "user", "content": "Second"}],
        context_id="second-context",
    )

    await core.process(first)
    await core.process(second)

    assert first.context_id != second.context_id
    assert adapter.context_ids == ["first-context", "second-context"]


@pytest.mark.asyncio
async def test_adapter_timeout_is_controlled() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": TimeoutAdapter()},
        timeout_seconds=0.01,
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.ERROR
    assert response.error_code == "ADAPTER_TIMEOUT"


@pytest.mark.asyncio
async def test_explicit_consequential_task_is_not_executed() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": SuccessfulProviderAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Send an email"}],
        task_type="unsupported",
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.UNSUPPORTED
    assert response.error_code == "UNSUPPORTED_TASK"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "metadata",
    [
        {"API_KEY": "upper-secret"},
        {"api_key": "lower-secret"},
        {"PaSsWoRd": "mixed-secret"},
        {"nested": {"password": "nested-secret"}},
        {"items": [{"access_token": "access-secret"}]},
        {"refresh_token": "refresh-secret"},
        {"authorization": "Bearer authorization-secret"},
        {"private_key": "private-secret"},
        {"client_secret": "client-secret"},
        {"bearer_token": "bearer-secret"},
        {"note": "token=innocuous-value"},
        {"native_name": "secret=innocuous-value"},
    ],
)
async def test_response_metadata_does_not_expose_unapproved_or_secret_values(
    metadata: dict,
) -> None:
    adapter = MetadataAdapter(metadata)
    core = OrchestrationCore(adapters={"text_generation": adapter})

    response = await core.process(
        IntelligenceRequest(messages=[{"role": "user", "content": "Hello"}])
    )

    assert response.status == ResponseStatus.COMPLETED
    assert response.metadata == {
        "provider_id": "mock",
        "model_id": "mock-chat-v1",
    }
    assert adapter.metadata == adapter.original_metadata


@pytest.mark.asyncio
async def test_response_metadata_preserves_approved_public_scalars() -> None:
    metadata = {
        "deterministic": True,
        "native_name": "English",
        "script": "Latn",
        "direction": "ltr",
        "context_id": "private-context-value",
        "unapproved": "not public",
    }
    adapter = MetadataAdapter(metadata)
    core = OrchestrationCore(adapters={"text_generation": adapter})

    response = await core.process(
        IntelligenceRequest(messages=[{"role": "user", "content": "Hello"}])
    )

    assert response.metadata == {
        "deterministic": True,
        "native_name": "English",
        "script": "Latn",
        "direction": "ltr",
        "provider_id": "mock",
        "model_id": "mock-chat-v1",
    }
    assert adapter.metadata == adapter.original_metadata
