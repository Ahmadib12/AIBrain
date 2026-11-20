from fastapi.testclient import TestClient
import asyncio

import pytest

from backend.app.api.v1.providers import (
    check_provider_health,
    provider_router,
)
from backend.app.providers.mock import MockAIProvider
from backend.app.providers.schemas import ProviderAvailability


def test_list_providers(client: TestClient) -> None:
    response = client.get("/api/v1/providers")

    assert response.status_code == 200
    mock = next(item for item in response.json() if item["id"] == "mock")
    assert mock["enabled"] is True
    assert mock["models"] == ["mock-chat-v1"]
    assert not {"api_key", "credential", "secret"} & mock.keys()


def test_provider_status(client: TestClient) -> None:
    response = client.get("/api/v1/providers/status")

    assert response.status_code == 200
    assert response.json()[0]["provider_id"] == "mock"
    assert response.json()[0]["availability"] == "unknown"


def test_provider_health_check(client: TestClient) -> None:
    response = client.post("/api/v1/providers/health/mock")

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


def test_provider_health_exception_is_structured(
    client: TestClient,
    monkeypatch,
) -> None:
    async def failed_health_check(self):
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(MockAIProvider, "health_check", failed_health_check)
    provider_router.health_monitor.record_success("other", latency_ms=5)

    response = client.post("/api/v1/providers/health/mock")

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

    response = client.post("/api/v1/providers/health/mock")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PROVIDER_HEALTH_CHECK_FAILED"


@pytest.mark.asyncio
async def test_provider_health_cancellation_is_propagated(monkeypatch) -> None:
    async def cancelled_health_check(self):
        raise asyncio.CancelledError()

    monkeypatch.setattr(MockAIProvider, "health_check", cancelled_health_check)

    with pytest.raises(asyncio.CancelledError):
        await check_provider_health("mock")
