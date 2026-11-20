from fastapi import FastAPI

from backend.app.api.v1.router import api_router
from backend.app.config import Settings
from backend.app.errors import register_error_handlers
from backend.app.logging import configure_logging


settings = Settings()
configure_logging(settings.log_level)

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AIBrain backend foundation",
)
register_error_handlers(app)
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}
