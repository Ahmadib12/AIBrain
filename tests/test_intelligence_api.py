import asyncio
import json
import logging

from fastapi.testclient import TestClient
import pytest

from backend.app.agli.core import AGLI
from backend.app.agli.registry import language_registry
from backend.app.api.v1.dependencies import get_intelligence_core
from backend.app.api.v1.providers import provider_router
from backend.app.intelligence.adapters import (
    AGLILanguageAdapter,
    AdapterResult,
    CapabilityAdapter,
    ProviderRoutingAdapter,
)
from backend.app.intelligence.core import OrchestrationCore
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.schemas import (
    IntelligenceRequest,
    IntelligenceResponse,
    ResponseStatus,
)
from backend.app.intelligence.trace import DecisionTraceBuilder
from backend.app.main import app
from backend.app.providers.fallback import FallbackExecutor
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.mock import MockAIProvider
from backend.app.providers.registry import ProviderRegistry
from backend.app.providers.router import ModelRouter
from backend.app.providers.schemas import ChatRequest, ChatResponse


class FailingAdapter(CapabilityAdapter):
    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        raise RuntimeError("internal provider secret detail")


class TrackingAdapter(CapabilityAdapter):
    def __init__(self) -> None:
        self.calls = 0

    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        self.calls += 1
        return AdapterResult(content="executed")


class CapturingProviderRouter:
    def __init__(self) -> None:
        self.request: ChatRequest | None = None

    async def route(self, request: ChatRequest) -> ChatResponse:
        self.request = request
        return ChatResponse(
            content="captured response",
            provider_id="mock",
            model_id="mock-chat-v1",
            latency_ms=0,
        )


def build_mock_provider_router() -> ModelRouter:
    registry = ProviderRegistry()
    registry.register(MockAIProvider())
    health = ProviderHealthMonitor()
    fallback = FallbackExecutor(
        health_monitor=health,
        timeout_seconds=1,
        max_attempts=1,
    )
    return ModelRouter(registry, health, fallback)


@pytest.fixture
def client_for_core():
    def create(core: OrchestrationCore) -> TestClient:
        app.dependency_overrides[get_intelligence_core] = lambda: core
        return TestClient(app)

    yield create
    app.dependency_overrides.pop(get_intelligence_core, None)


def test_successful_provider_intelligence_request(client_for_core) -> None:
    core = OrchestrationCore(
        adapters={
            "text_generation": ProviderRoutingAdapter(build_mock_provider_router())
        }
    )
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["content"] == "[mock response] Hello"
    assert body["metadata"]["provider_id"] == "mock"
    assert body["metadata"]["model_id"] == "mock-chat-v1"
    assert body["decision_trace"]["trace_id"] == body["request_id"]
    assert body["decision_trace"]["selected_capability"] == "text_generation"
    assert body["decision_trace"]["execution_status"] == "succeeded"
    assert IntelligenceResponse.model_validate(body).status == ResponseStatus.COMPLETED


def test_openapi_documents_optional_trace_on_internal_error() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/api/v1/intelligence/process"]["post"]
    response_schema = operation["responses"]["500"]["content"][
        "application/json"
    ]["schema"]
    if "$ref" in response_schema:
        component_name = response_schema["$ref"].rsplit("/", 1)[-1]
        response_schema = schema["components"]["schemas"][component_name]

    assert "decision_trace" in response_schema["properties"]
    assert "decision_trace" not in response_schema.get("required", [])


def test_trace_recording_failure_does_not_turn_request_into_500(
    client_for_core,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "API_TRACE_RECORDING_SECRET_SENTINEL_X4"

    def fail_record(self, *args, **kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(
        DecisionTraceBuilder,
        "record_classification",
        fail_record,
    )
    core = OrchestrationCore(adapters={"text_generation": TrackingAdapter()})
    with caplog.at_level(logging.WARNING, logger="aibrain.intelligence"):
        with client_for_core(core) as client:
            response = client.post(
                "/api/v1/intelligence/process",
                json={"messages": [{"role": "user", "content": "Hello"}]},
            )

    assert response.status_code == 200
    assert response.json()["content"] == "executed"
    assert response.json()["decision_trace"] is None
    assert secret not in response.text
    assert secret not in caplog.text


def test_invalid_intelligence_request_body_returns_422(client_for_core) -> None:
    core = OrchestrationCore()
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={"messages": [{"role": "system", "content": "untrusted system"}]},
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    details = response.json()["error"]["details"]
    assert any(
        detail["loc"] == ["body", "messages", 0, "role"]
        and detail["type"] == "enum"
        for detail in details
    )
    assert all(set(detail) == {"type", "loc"} for detail in details)


@pytest.mark.parametrize(
    ("body", "secret"),
    [
        (
            {"messages": [{"role": "user", "content": "password=MESSAGE_SECRET_X91"}]},
            "MESSAGE_SECRET_X91",
        ),
        (
            {
                "messages": [{"role": "user", "content": "Hello"}],
                "metadata": {"api_key": "METADATA_SECRET_Y82"},
            },
            "METADATA_SECRET_Y82",
        ),
    ],
)
def test_credential_validation_returns_sanitized_422(
    client_for_core,
    caplog,
    body: dict,
    secret: str,
) -> None:
    core = OrchestrationCore()
    with client_for_core(core) as client:
        with caplog.at_level(logging.WARNING, logger="aibrain.errors"):
            response = client.post("/api/v1/intelligence/process", json=body)

    assert response.status_code == 422
    assert secret not in response.text
    assert secret not in caplog.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_credential_like_context_id_is_rejected_without_leaking_value(
    client_for_core,
    caplog,
) -> None:
    secret = "CONTEXT_SECRET_Z73"
    core = OrchestrationCore()
    with client_for_core(core) as client:
        with caplog.at_level(logging.WARNING, logger="aibrain.errors"):
            response = client.post(
                "/api/v1/intelligence/process",
                json={
                    "messages": [{"role": "user", "content": "Hello"}],
                    "context_id": f"api_key={secret}",
                },
            )

    assert response.status_code == 422
    assert secret not in response.text
    assert secret not in caplog.text


def test_normal_context_id_works_and_is_not_forwarded_to_provider(
    client_for_core,
) -> None:
    provider = CapturingProviderRouter()
    core = OrchestrationCore(
        adapters={"text_generation": ProviderRoutingAdapter(provider)}
    )
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={
                "messages": [{"role": "user", "content": "Hello"}],
                "context_id": "normal-context-123",
            },
        )

    assert response.status_code == 200
    assert response.json()["content"] == "captured response"
    assert "context_id" not in response.json()
    assert "context_id" not in response.json()["metadata"]
    assert provider.request is not None
    assert provider.request.metadata == {}


def test_unsupported_intelligence_task_returns_standard_response(
    client_for_core,
) -> None:
    tracker = TrackingAdapter()
    core = OrchestrationCore(adapters={"text_generation": tracker})
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={"messages": [{"role": "user", "content": "Send an email"}]},
        )

    assert response.status_code == 400
    body = IntelligenceResponse.model_validate(response.json())
    assert body.status == ResponseStatus.UNSUPPORTED
    assert body.decision_trace is not None
    assert body.decision_trace.execution_status.value == "unsupported"
    assert tracker.calls == 0


def test_unavailable_capability_returns_503(client_for_core) -> None:
    core = OrchestrationCore()
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )

    assert response.status_code == 503
    body = IntelligenceResponse.model_validate(response.json())
    assert body.error_code == "CAPABILITY_UNAVAILABLE"
    assert body.decision_trace is not None
    assert body.decision_trace.capability_available is False
    assert body.decision_trace.execution_status.value == "not_attempted"


def test_agli_adapter_delegation(client_for_core) -> None:
    core = OrchestrationCore(
        adapters={
            "language_lookup": AGLILanguageAdapter(AGLI(language_registry))
        }
    )
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={
                "messages": [{"role": "user", "content": "Lookup language"}],
                "task_type": "language_lookup",
                "language_code": "en",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["content"] == "English (en)"
    assert body["metadata"]["native_name"] == "English"
    assert body["decision_trace"]["selected_capability"] == "language_lookup"
    assert body["decision_trace"]["execution_status"] == "succeeded"


def test_adapter_failure_is_sanitized(client_for_core) -> None:
    core = OrchestrationCore(
        adapters={"text_generation": FailingAdapter()}
    )
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )

    assert response.status_code == 502
    assert "internal provider secret detail" not in response.text
    assert response.json()["error_code"] == "ADAPTER_FAILURE"
    assert response.json()["decision_trace"]["error_code"] == "ADAPTER_FAILURE"
    assert response.json()["decision_trace"]["execution_status"] == "failed"


def test_fastapi_dependency_override_is_used(client_for_core) -> None:
    core = OrchestrationCore(
        adapters={"text_generation": ProviderRoutingAdapter(build_mock_provider_router())}
    )
    with client_for_core(core) as client:
        response = client.post(
            "/api/v1/intelligence/process",
            json={"messages": [{"role": "user", "content": "Override test"}]},
        )

    assert response.status_code == 200
    assert response.json()["content"] == "[mock response] Override test"


def test_existing_health_and_provider_endpoints_remain_functional() -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        providers = client.get("/api/v1/providers")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert providers.status_code == 200
    assert any(provider["id"] == "mock" for provider in providers.json())


@pytest.mark.asyncio
async def test_intelligence_endpoint_propagates_cancellation() -> None:
    from backend.app.api.v1.intelligence import process_intelligence

    class CancellingCore:
        async def process(self, request: IntelligenceRequest):
            raise asyncio.CancelledError()

    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )
    with pytest.raises(asyncio.CancelledError):
        await process_intelligence(request, core=CancellingCore())


@pytest.mark.asyncio
async def test_unexpected_core_failure_has_safe_trace(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from backend.app.api.v1.intelligence import process_intelligence

    secret = "API_CORE_FAILURE_SECRET_SENTINEL_V7"

    class FailingCore:
        async def process(self, request: IntelligenceRequest):
            raise RuntimeError(secret)

    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Synthetic request"}]
    )
    with caplog.at_level(logging.ERROR, logger="aibrain.intelligence"):
        response = await process_intelligence(request, core=FailingCore())
    body = json.loads(response.body)
    trace = body["decision_trace"]

    assert response.status_code == 500
    assert body["error_code"] == "INTELLIGENCE_FAILURE"
    assert trace["decision_reason_code"] == "core_execution_failed"
    assert trace["execution_status"] == "failed"
    assert trace["error_code"] == "INTELLIGENCE_FAILURE"
    assert secret not in response.body.decode()
    assert secret not in caplog.text


def test_default_dependency_registers_only_available_integrations() -> None:
    core = get_intelligence_core()
    capability_ids = {
        capability.capability_id
        for capability in core.capability_registry.list()
    }

    assert "language_lookup" in capability_ids
    has_available_provider = any(
        provider.enabled
        and provider_router.health_monitor.is_available(provider.id)
        for provider in provider_router.registry.list()
    )
    if has_available_provider:
        assert "text_generation" in capability_ids
    else:
        assert "text_generation" not in capability_ids
    assert "provider_status" not in capability_ids
