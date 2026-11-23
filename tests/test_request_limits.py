import asyncio
import json

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.middleware import RequestBodyLimitMiddleware


def test_http_request_body_over_configured_limit_is_rejected() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/providers/chat",
            json={"messages": [{"role": "user", "content": "x" * 1_100_000}]},
        )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_BODY_TOO_LARGE"


def test_body_limit_is_enforced_without_content_length() -> None:
    received = [
        {"type": "http.request", "body": b"1234", "more_body": True},
        {"type": "http.request", "body": b"5678", "more_body": False},
    ]
    sent = []

    async def receive():
        return received.pop(0)

    async def send(message):
        sent.append(message)

    async def app_that_must_not_run(scope, receive, send):
        raise AssertionError("Application received an oversized body")

    middleware = RequestBodyLimitMiddleware(
        app_that_must_not_run,
        max_body_bytes=7,
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/test",
        "headers": [],
    }

    asyncio.run(middleware(scope, receive, send))

    assert sent[0]["status"] == 413
    payload = json.loads(sent[1]["body"])
    assert payload["error"]["code"] == "REQUEST_BODY_TOO_LARGE"
    assert payload["error"]["path"] == "/test"
