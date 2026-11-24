import json
from collections.abc import Awaitable, Callable
from typing import Any

ASGIMessage = dict[str, Any]
ASGIReceive = Callable[[], Awaitable[ASGIMessage]]
ASGISend = Callable[[ASGIMessage], Awaitable[None]]


class RequestBodyLimitMiddleware:
    """Enforce a request-body limit using actual received bytes."""

    def __init__(
        self, app: Any, *, max_body_bytes: int,
        path_limits: dict[str, int] | None = None,
    ) -> None:
        if max_body_bytes < 1:
            raise ValueError("Maximum request body size must be positive")
        normalized_limits = path_limits or {}
        if any(
            not isinstance(path, str) or not path.startswith("/")
            or not isinstance(limit, int) or isinstance(limit, bool) or limit < 1
            for path, limit in normalized_limits.items()
        ):
            raise ValueError("Path-specific request body limits are invalid")
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.path_limits = normalized_limits

    def _limit_for_scope(self, scope: dict[str, Any]) -> int:
        path = scope.get("path", "")
        matches = [
            (prefix, limit)
            for prefix, limit in self.path_limits.items()
            if path == prefix or path.startswith(prefix.rstrip("/") + "/")
        ]
        return max(matches, key=lambda item: len(item[0]))[1] if matches else self.max_body_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body_limit = self._limit_for_scope(scope)
        headers = dict(scope.get("headers", []))
        declared_length = headers.get(b"content-length")
        if declared_length is not None:
            try:
                if int(declared_length) > body_limit:
                    await self._reject(scope, send)
                    return
            except ValueError:
                pass

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue

            body.extend(message.get("body", b""))
            if len(body) > body_limit:
                await self._reject(scope, send)
                return
            if not message.get("more_body", False):
                break

        first_message = True

        async def replay_receive():
            nonlocal first_message
            if first_message:
                first_message = False
                return {
                    "type": "http.request",
                    "body": bytes(body),
                    "more_body": False,
                }
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(scope, send) -> None:
        payload = json.dumps({
            "error": {
                "code": "REQUEST_BODY_TOO_LARGE",
                "message": "The request body exceeds the configured size limit",
                "path": scope.get("path", ""),
            }
        }).encode("utf-8")

        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": payload})


class SecurityHeadersMiddleware:
    """Add baseline browser security headers to HTTP responses."""

    SECURITY_HEADERS = (
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (
            b"permissions-policy",
            b"camera=(), microphone=(), geolocation=()",
        ),
    )

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                existing = {
                    name.lower()
                    for name, _ in message.get("headers", [])
                }
                headers = list(message.get("headers", []))

                for name, value in self.SECURITY_HEADERS:
                    if name not in existing:
                        headers.append((name, value))

                message = {**message, "headers": headers}

            await send(message)

        await self.app(scope, receive, send_with_security_headers)
