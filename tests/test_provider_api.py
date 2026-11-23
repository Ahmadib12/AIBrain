from fastapi.testclient import TestClient
import asyncio

import pytest

from backend.app.api.v1.providers import (
    check_provider_health,
    provider_router,
)
from backend.app.providers.mock import MockAIProvider
from backend.app.providers.schemas import ProviderAvailability


def test_list_providers(client: TestClient,
    operator_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/providers", headers=operator_headers)

    assert response.status_code == 200
    mock = next(item for item in response.json() if item["id"] == "mock")
    assert mock["enabled"] is True
    assert mock["models"] == ["mock-chat-v1"]
    assert not {"api_key", "credential", "secret"} & mock.keys()


def test_provider_status(client: TestClient,
    operator_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/providers/status", headers=operator_headers)

    assert response.status_code == 200
    assert response.json()[0]["provider_id"] == "mock"
    assert response.json()[0]["availability"] == "unknown"


def test_provider_health_check(client: TestClient,
    operator_headers: dict[str, str]) -> None:
    response = client.post("/api/v1/providers/health/mock", headers=operator_headers)

    assert response.status_code == 200
    assert response.json()["provider_id"] == "mock"
    assert response.json()["availability"] == "available"


def test_provider_chat(client: TestClient) -> None:
    response = client.post(
        "/api/v1/providers/chat",
        json={"messages": [{"role": "user", "content": "Hello"}]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider_id"] == "mock"
    assert body["content"] == "[mock response] Hello"
    assert "api_key" not in body


def test_provider_chat_unknown_provider(client: TestClient) -> None:
    response = client.post(
        "/api/v1/providers/chat",
        json={
            "messages": [{"role": "user", "content": "Hello"}],
            "provider": "missing",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_PROVIDER_REQUEST"


def test_provider_chat_invalid_model(client: TestClient) -> None:
    response = client.post(
        "/api/v1/providers/chat",
        json={
            "messages": [{"role": "user", "content": "Hello"}],
            "provider": "mock",
            "model": "missing-model",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_PROVIDER_REQUEST"
    assert "missing-model" not in response.text


@pytest.mark.parametrize(
    ("metadata"),
    [
        {"api_key": "secret"},
        {"nested": {"item": {"deep": {"too": {"deep": "value"}}}}},
        {"items": list(range(21))},
        {"large": "x" * 4097},
        {"note": "Bearer abcdefghijklmnop"},
    ],
)
def test_provider_chat_metadata_is_validated_safely(
    client: TestClient,
    metadata: dict,
) -> None:
    response = client.post(
        "/api/v1/providers/chat",
        json={
            "messages": [{"role": "user", "content": "Hello"}],
            "metadata": metadata,
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_provider_chat_exhaustion_has_no_routing_or_exception_details(
    client: TestClient,
    monkeypatch,
) -> None:
    async def unavailable_health_check(self):
        from backend.app.providers.schemas import ProviderHealth
        return ProviderHealth(
            provider_id=self.id,
            availability=ProviderAvailability.UNAVAILABLE,
        )

    async def unavailable_generate(self, request):
        from backend.app.providers.errors import ProviderUnavailableError
        raise ProviderUnavailableError(
            self.id,
            "PROVIDER_CHAT_UNAVAILABLE_SECRET_SENTINEL",
        )

    monkeypatch.setattr(MockAIProvider, "health_check", unavailable_health_check)
    monkeypatch.setattr(MockAIProvider, "generate", unavailable_generate)

    response = client.post(
        "/api/v1/providers/chat",
        json={"messages": [{"role": "user", "content": "Hello"}]},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ALL_PROVIDERS_FAILED"
    assert "routing_summary" not in response.text
    assert "PROVIDER_CHAT_UNAVAILABLE_SECRET_SENTINEL" not in response.text


def test_provider_health_exception_is_structured(
    client: TestClient,
    operator_headers: dict[str, str],
    monkeypatch,
) -> None:
    async def failed_health_check(self):
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(MockAIProvider, "health_check", failed_health_check)
    provider_router.health_monitor.record_success("other", latency_ms=5)

    response = client.post("/api/v1/providers/health/mock", headers=operator_headers)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PROVIDER_HEALTH_CHECK_FAILED"
    assert "sensitive" not in str(response.json())
    assert (
        provider_router.health_monitor.get("mock").availability
        == ProviderAvailability.UNAVAILABLE
    )
    assert (
        provider_router.health_monitor.get("other").availability
        == ProviderAvailability.AVAILABLE
    )


def test_provider_reported_unavailable_is_structured(
    client: TestClient,
    operator_headers: dict[str, str],
    monkeypatch,
) -> None:
    async def unavailable_health_check(self):
        from backend.app.providers.schemas import ProviderHealth

        return ProviderHealth(
            provider_id="mock",
            availability=ProviderAvailability.UNAVAILABLE,
        )

    monkeypatch.setattr(
        MockAIProvider,
        "health_check",
        unavailable_health_check,
    )

    response = client.post("/api/v1/providers/health/mock", headers=operator_headers)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PROVIDER_HEALTH_CHECK_FAILED"


@pytest.mark.asyncio
async def test_provider_health_cancellation_is_propagated(monkeypatch) -> None:
    async def cancelled_health_check(self):
        raise asyncio.CancelledError()

    monkeypatch.setattr(MockAIProvider, "health_check", cancelled_health_check)

    with pytest.raises(asyncio.CancelledError):
        await check_provider_health("mock")


def test_provider_health_timeout_is_structured(
    client: TestClient,
    operator_headers: dict[str, str],
    monkeypatch,
) -> None:
    async def slow_health_check(self):
        await asyncio.sleep(1)
        return await MockAIProvider().health_check()

    monkeypatch.setattr(MockAIProvider, "health_check", slow_health_check)
    monkeypatch.setenv(
        "AIBRAIN_PROVIDER_HEALTH_CHECK_TIMEOUT_SECONDS",
        "0.01",
    )

    response = client.post("/api/v1/providers/health/mock", headers=operator_headers)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "PROVIDER_HEALTH_TIMEOUT"
