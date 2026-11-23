from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.api.v1.router import api_router
from backend.app.config import get_settings
from backend.app.errors import register_error_handlers
from backend.app.logging import configure_logging
from backend.app.middleware import RequestBodyLimitMiddleware, SecurityHeadersMiddleware
from backend.app.app_state import get_app_state, reset_app_state


settings = get_settings()
configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_app_state(settings)
    try:
        yield
    finally:
        reset_app_state()


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AIBrain backend foundation",
    lifespan=lifespan,
)
register_error_handlers(app)
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_bytes=settings.max_request_body_bytes,
)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}
