import asyncio

from backend.app.middleware import RequestBodyLimitMiddleware


def run_request(middleware, path: str, body: bytes, *, declared_length=True):
    messages = []
    app_called = []

    async def app(scope, receive, send):
        app_called.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "path": path,
        "headers": (
            [(b"content-length", str(len(body)).encode("ascii"))]
            if declared_length else []
        ),
    }
    middleware.app = app
    asyncio.run(middleware(scope, receive, send))
    return messages, app_called


def test_runner_evidence_path_uses_its_own_bounded_limit():
    middleware = RequestBodyLimitMiddleware(
        lambda *args: None,
        max_body_bytes=1024,
        path_limits={"/api/v1/tools/runner/evidence": 4096},
    )
    messages, app_called = run_request(
        middleware, "/api/v1/tools/runner/evidence", b"x" * 2048
    )
    assert app_called == [True]
    assert messages[0]["status"] == 200


def test_runner_evidence_limit_does_not_apply_to_similar_paths():
    middleware = RequestBodyLimitMiddleware(
        lambda *args: None,
        max_body_bytes=1024,
        path_limits={"/api/v1/tools/runner/evidence": 4096},
    )
    messages, app_called = run_request(
        middleware, "/api/v1/tools/runner/evidence-evil", b"x" * 2048
    )
    assert app_called == []
    assert messages[0]["status"] == 413


def test_runner_evidence_limit_applies_to_nested_attestation_paths():
    middleware = RequestBodyLimitMiddleware(
        lambda *args: None,
        max_body_bytes=1024,
        path_limits={"/api/v1/tools/runner/evidence": 4096},
    )
    messages, app_called = run_request(
        middleware,
        "/api/v1/tools/runner/evidence/package-1/attest",
        b"x" * 2048,
    )
    assert app_called == [True]
    assert messages[0]["status"] == 200


def test_streamed_body_is_checked_without_content_length():
    middleware = RequestBodyLimitMiddleware(
        lambda *args: None,
        max_body_bytes=1024,
        path_limits={"/api/v1/tools/runner/evidence": 4096},
    )
    messages, app_called = run_request(
        middleware,
        "/api/v1/tools/other",
        b"x" * 2048,
        declared_length=False,
    )
    assert app_called == []
    assert messages[0]["status"] == 413
