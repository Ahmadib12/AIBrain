import pytest
from fastapi.testclient import TestClient

from backend.app import concurrency
from backend.app.concurrency import AIRequestLimiter
from backend.app.main import app


def test_ai_request_limiter_rejects_when_capacity_is_full() -> None:
    limiter = AIRequestLimiter(1)

    assert limiter.acquire() is True
    assert limiter.acquire() is False

    limiter.release()

    assert limiter.acquire() is True
    limiter.release()


def test_ai_routes_reject_requests_when_shared_capacity_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limiter = AIRequestLimiter(1)
    assert limiter.acquire() is True
    monkeypatch.setattr(concurrency, "ai_request_limiter", limiter)

    payload = {"messages": [{"role": "user", "content": "Hello"}]}

    try:
        with TestClient(app) as client:
            paths = (
                "/api/v1/providers/chat",
                "/api/v1/intelligence/process",
                "/api/v1/intelligence/process/stream",
            )
            for path in paths:
                response = client.post(path, json=payload)
                assert response.status_code == 503
                assert response.json()["error"]["code"] == (
                    "AI_CAPACITY_EXCEEDED"
                )
                assert response.headers["retry-after"] == "1"
    finally:
        limiter.release()


def test_ai_capacity_is_released_after_request_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limiter = AIRequestLimiter(1)
    monkeypatch.setattr(concurrency, "ai_request_limiter", limiter)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/providers/chat",
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )

    assert response.status_code == 200
    assert limiter.acquire() is True
    limiter.release()
