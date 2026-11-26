from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.api.v1.router import api_router
from backend.app.config import get_settings
from backend.app.errors import register_error_handlers
from backend.app.logging import configure_logging
from backend.app.middleware import RequestBodyLimitMiddleware, SecurityHeadersMiddleware
from backend.app.app_state import get_app_state, reset_app_state
from backend.app.tools.recovery import ToolExecutionRecoveryWorker
from backend.app.persistence.memory_retention import MemoryRetentionWorker
from backend.app.persistence.integration_expiry import IntegrationConnectionExpiryWorker
from backend.app.persistence.integration_dispatch_recovery import IntegrationDispatchRecoveryWorker
from backend.app.persistence.security_notification_transport import SmtpSecurityNotificationTransport
from backend.app.persistence.security_notification_worker import SecurityNotificationDeliveryWorker


settings = get_settings()
configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    state = get_app_state(settings)
    recovery_worker = ToolExecutionRecoveryWorker(
        state.tool_requests,
        interval_seconds=settings.tool_execution_recovery_interval_seconds,
        stale_after_seconds=settings.tool_execution_stale_after_seconds,
    )
    memory_retention_worker = MemoryRetentionWorker(
        state.memory,
        interval_seconds=settings.memory_retention_interval_seconds,
    )
    integration_expiry_worker = IntegrationConnectionExpiryWorker(
        state.integration_connections,
        interval_seconds=settings.integration_expiry_interval_seconds,
    )
    integration_dispatch_recovery_worker = IntegrationDispatchRecoveryWorker(
        state.integration_orchestrator,
        interval_seconds=settings.integration_dispatch_recovery_interval_seconds,
        stale_after_seconds=settings.integration_dispatch_stale_after_seconds,
    )
    notification_worker = None
    if settings.security_notification_delivery_enabled:
        notification_worker = SecurityNotificationDeliveryWorker(
            state.security_notifications,
            SmtpSecurityNotificationTransport(settings),
            interval_seconds=settings.security_notification_worker_interval_seconds,
            batch_size=settings.security_notification_batch_size,
        )
    try:
        await recovery_worker.start()
        await memory_retention_worker.start()
        await integration_expiry_worker.start()
        await integration_dispatch_recovery_worker.start()
        if notification_worker is not None:
            await notification_worker.start()
        yield
    finally:
        try:
            if notification_worker is not None:
                await notification_worker.stop()
        finally:
            try:
                await integration_dispatch_recovery_worker.stop()
        finally:
            try:
                await integration_expiry_worker.stop()
            finally:
                try:
                    await memory_retention_worker.stop()
                finally:
                    try:
                        await recovery_worker.stop()
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
    path_limits={
        f"{settings.api_v1_prefix}/tools/runner/evidence":
            settings.runner_evidence_max_request_body_bytes,
    },
)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}
