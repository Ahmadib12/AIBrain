from collections.abc import AsyncIterator
from threading import BoundedSemaphore

from fastapi import HTTPException

from backend.app.config import get_settings


class AIRequestLimiter:
    """Thread-safe, process-local limit for concurrent AI requests."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("AI concurrency limit must be positive")
        self._semaphore = BoundedSemaphore(limit)

    def acquire(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release(self) -> None:
        self._semaphore.release()


ai_request_limiter = AIRequestLimiter(
    get_settings().ai_max_concurrent_requests
)


async def require_ai_capacity() -> AsyncIterator[None]:
    if not ai_request_limiter.acquire():
        raise HTTPException(
            status_code=503,
            detail={
                "code": "AI_CAPACITY_EXCEEDED",
                "message": "AI processing capacity is currently full; retry later",
            },
            headers={"Retry-After": "1"},
        )
    try:
        yield
    finally:
        ai_request_limiter.release()
