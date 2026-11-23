import asyncio
from copy import deepcopy
import logging

import pytest

from backend.app.intelligence.adapters import (
    AGLILanguageAdapter,
    AdapterFailureError,
    AdapterResult,
    CapabilityAdapter,
    InvalidAdapterResultError,
    ProviderRoutingAdapter,
)
from backend.app.intelligence.capabilities import (
    CapabilityMetadata,
    CapabilityRegistry,
)
from backend.app.intelligence.core import (
    CentralIntelligenceCore,
    OrchestrationCore,
)
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.trace import (
    DecisionTraceBuilder,
    ProviderFailureCategory,
)
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
from backend.app.providers.interface import AIProvider
from backend.app.providers.errors import ProviderTimeoutError
from backend.app.providers.schemas import ChatRequest, ChatResponse
from backend.app.providers.routing import (
    ProviderRoutingSummary,
    SafeProviderFailureCategory,
)


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
    trace = response.decision_trace
    assert trace is not None
    assert str(trace.trace_id) == response.request_id
    assert trace.task_type.value == "conversation"
    assert trace.classification_status.value == "default"
    assert trace.classification_reason_code.value == "default_conversation"
    assert trace.considered_capability.value == "text_generation"
    assert trace.selected_capability.value == "text_generation"
    assert trace.capability_available is True
    assert trace.decision_reason_code.value == "capability_selected"
    assert trace.execution_status.value == "succeeded"
    assert trace.error_code is None
    assert "[mock provider] Hello" not in trace.model_dump_json()


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
    assert response.decision_trace is not None
    assert response.decision_trace.considered_capability.value == "language_lookup"
    assert response.decision_trace.selected_capability.value == "language_lookup"
    assert response.decision_trace.classification_reason_code.value == "explicit_task"
    assert response.decision_trace.execution_status.value == "succeeded"


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
    assert response.decision_trace is not None
    assert response.decision_trace.classification_reason_code.value == (
        "unsupported_action"
    )
    assert response.decision_trace.considered_capability is None
    assert response.decision_trace.selected_capability is None
    assert response.decision_trace.execution_status.value == "unsupported"
    assert response.decision_trace.error_code.value == "UNSUPPORTED_TASK"


@pytest.mark.asyncio
async def test_unavailable_capability_is_not_executed() -> None:
    core = OrchestrationCore()
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.ERROR
    assert response.error_code == "CAPABILITY_UNAVAILABLE"
    assert response.decision_trace is not None
    assert response.decision_trace.considered_capability.value == "text_generation"
    assert response.decision_trace.selected_capability is None
    assert response.decision_trace.capability_available is False
    assert response.decision_trace.decision_reason_code.value == (
        "capability_unavailable"
    )
    assert response.decision_trace.execution_status.value == "not_attempted"
    assert response.decision_trace.error_code.value == "CAPABILITY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_missing_adapter_is_traced_without_changing_response() -> None:
    registry = CapabilityRegistry()
    registry.register(CapabilityMetadata(
        capability_id="text_generation",
        name="Text Generation",
        implemented=True,
        available=True,
    ))
    core = OrchestrationCore(capability_registry=registry)
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )

    response = await core.process(request)

    assert response.status == ResponseStatus.ERROR
    assert response.error_code == "ADAPTER_UNAVAILABLE"
    assert response.content is None
    assert response.selected_capabilities == ()
    assert response.decision_trace is not None
    assert response.decision_trace.considered_capability.value == "text_generation"
    assert response.decision_trace.selected_capability is None
    assert response.decision_trace.capability_available is True
    assert response.decision_trace.decision_reason_code.value == (
        "adapter_unavailable"
    )
    assert response.decision_trace.execution_status.value == "not_attempted"
    assert response.decision_trace.error_code.value == "ADAPTER_UNAVAILABLE"


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
    assert response.decision_trace is not None
    assert response.decision_trace.selected_capability.value == "text_generation"
    assert response.decision_trace.execution_status.value == "failed"
    assert response.decision_trace.error_code.value == "ADAPTER_FAILURE"


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

    first_response = await core.process(first)
    second_response = await core.process(second)

    assert first.context_id != second.context_id
    assert adapter.context_ids == ["first-context", "second-context"]
    assert first_response.decision_trace is not None
    assert second_response.decision_trace is not None
    assert first_response.decision_trace.trace_id != second_response.decision_trace.trace_id
    assert str(first_response.decision_trace.trace_id) == first_response.request_id
    assert str(second_response.decision_trace.trace_id) == second_response.request_id


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
    assert response.decision_trace is not None
    assert response.decision_trace.selected_capability.value == "text_generation"
    assert response.decision_trace.execution_status.value == "timed_out"
    assert response.decision_trace.error_code.value == "ADAPTER_TIMEOUT"


@pytest.mark.asyncio
async def test_trace_excludes_input_and_nested_sensitive_adapter_metadata() -> None:
    input_sentinel = "TRACE_INPUT_SENTINEL_N4"
    context_sentinel = "TRACE_CONTEXT_SENTINEL_P6"
    secret = "TRACE_NESTED_SECRET_SENTINEL_R8"
    adapter = MetadataAdapter({
        "nested": {"password": secret},
        "authorization": {"bearer_token": secret},
    })
    core = OrchestrationCore(adapters={"text_generation": adapter})

    response = await core.process(
        IntelligenceRequest(
            messages=[{"role": "user", "content": input_sentinel}],
            context_id=context_sentinel,
        )
    )

    assert response.decision_trace is not None
    serialized_trace = response.decision_trace.model_dump_json()
    assert input_sentinel not in serialized_trace
    assert context_sentinel not in serialized_trace
    assert secret not in serialized_trace
    assert "password" not in serialized_trace
    assert "authorization" not in serialized_trace
    assert "metadata" not in serialized_trace

    explicit_secret = "TRACE_EXPLICIT_SECRET_SENTINEL_T3"
    unsupported = await core.process(
        IntelligenceRequest(
            messages=[{"role": "user", "content": "Synthetic request"}],
            task_type=f"api_key={explicit_secret}",
        )
    )
    assert unsupported.decision_trace is not None
    assert explicit_secret not in unsupported.decision_trace.model_dump_json()
    assert (
        unsupported.decision_trace.classification_reason_code.value
        == "unknown_explicit_task"
    )


@pytest.mark.parametrize(
    "failing_method",
    (
        "__init__",
        "record_classification",
        "record_selected_capability",
        "build",
    ),
)
@pytest.mark.asyncio
async def test_trace_recording_failure_does_not_break_request(
    failing_method: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "TRACE_FAILURE_SECRET_SENTINEL_W2"

    def fail_trace(self, *args, **kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(DecisionTraceBuilder, failing_method, fail_trace)
    core = OrchestrationCore(
        adapters={"text_generation": SuccessfulProviderAdapter()}
    )

    with caplog.at_level(logging.WARNING, logger="aibrain.intelligence"):
        response = await core.process(
            IntelligenceRequest(
                messages=[{"role": "user", "content": "Hello"}]
            )
        )

    assert response.status == ResponseStatus.COMPLETED
    assert response.content == "[mock provider] Hello"
    assert response.selected_capabilities == ("text_generation",)
    assert response.decision_trace is None
    assert "Decision trace recording failed" in caplog.text
    assert secret not in caplog.text


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


class EndToEndTimeoutProvider(AIProvider):
    @property
    def id(self) -> str:
        return "end-to-end-timeout"

    @property
    def name(self) -> str:
        return "End-to-end timeout provider"

    @property
    def priority(self) -> int:
        return 100

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
        await asyncio.sleep(1)
        raise AssertionError("provider should time out")

    async def health_check(self):
        return await MockAIProvider().health_check()


class EndToEndSuccessProvider(AIProvider):
    @property
    def id(self) -> str:
        return "end-to-end-success"

    @property
    def name(self) -> str:
        return "End-to-end success provider"

    @property
    def priority(self) -> int:
        return 50

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
            content="end-to-end fallback success",
            provider_id=self.id,
            model_id=self.models[0],
            latency_ms=1,
        )

    async def health_check(self):
        return await MockAIProvider().health_check()


class RoutingSummaryAdapter(CapabilityAdapter):
    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        context.routing_summary = ProviderRoutingSummary(
            provider_attempt_count=2,
            retry_count=1,
            fallback_attempted=True,
            fallback_succeeded=True,
            intermediate_failure_categories=(
                SafeProviderFailureCategory.PROVIDER_TIMEOUT,
            ),
        )
        return AdapterResult(
            content="[mock provider] fallback succeeded",
            provider_id="public-success-provider",
            model_id="public-success-model",
        )


@pytest.mark.asyncio
async def test_successful_fallback_trace_contains_only_safe_summary() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": RoutingSummaryAdapter()}
    )
    response = await core.process(
        IntelligenceRequest(
            messages=[{
                "role": "user",
                "content": "provider-fallback-secret-sentinel",
            }],
            context_id="provider-context-secret-sentinel",
        )
    )

    assert response.status == ResponseStatus.COMPLETED
    trace = response.decision_trace
    assert trace is not None
    assert trace.fallback_attempted is True
    assert trace.fallback_succeeded is True
    assert trace.retry_count == 1
    assert trace.provider_attempt_count == 2
    assert trace.intermediate_failure_categories == (
        ProviderFailureCategory.PROVIDER_TIMEOUT,
    )
    serialized = trace.model_dump_json()
    assert "provider-fallback-secret-sentinel" not in serialized
    assert "provider-context-secret-sentinel" not in serialized


@pytest.mark.asyncio
async def test_real_provider_routing_fallback_trace_is_safe() -> None:
    registry = ProviderRegistry()
    registry.register(EndToEndTimeoutProvider())
    registry.register(EndToEndSuccessProvider())
    monitor = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=monitor,
        timeout_seconds=0.01,
        max_attempts=1,
    )
    router = ModelRouter(registry, monitor, fallback, fallback_enabled=True)
    core = OrchestrationCore(
        adapters={"text_generation": ProviderRoutingAdapter(router)},
        timeout_seconds=1,
    )

    response = await core.process(
        IntelligenceRequest(
            messages=[{
                "role": "user",
                "content": "REAL_FALLBACK_USER_SENTINEL",
            }],
            allow_fallback=True,
        )
    )

    assert response.status == ResponseStatus.COMPLETED
    assert response.content == "end-to-end fallback success"
    trace = response.decision_trace
    assert trace is not None
    assert trace.fallback_attempted is True
    assert trace.fallback_succeeded is True
    assert trace.provider_attempt_count == 2
    assert trace.retry_count == 1
    assert trace.intermediate_failure_categories == (
        ProviderFailureCategory.PROVIDER_TIMEOUT,
    )
    serialized = trace.model_dump_json()
    assert "REAL_FALLBACK_USER_SENTINEL" not in serialized
    assert "end-to-end-timeout" not in serialized
    assert "end-to-end-success" not in serialized
    assert "test-chat-v1" not in serialized
