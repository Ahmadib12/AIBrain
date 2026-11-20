import asyncio

from fastapi import APIRouter, HTTPException

from backend.app.config import Settings
from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
)
from backend.app.providers.runtime import build_provider_router
from backend.app.providers.schemas import (
    ChatRequest,
    ChatResponse,
    ProviderHealth,
    ProviderInfo,
)


router = APIRouter(prefix="/providers", tags=["providers"])
provider_router = build_provider_router(Settings())


@router.get("", response_model=list[ProviderInfo])
async def list_providers() -> list[ProviderInfo]:
    return [
        ProviderInfo(
            id=provider.id,
            name=provider.name,
            enabled=provider.enabled,
            priority=provider.priority,
            models=provider.models,
            capabilities=provider.capabilities,
        )
        for provider in provider_router.registry.list()
    ]


@router.get("/status", response_model=list[ProviderHealth])
async def provider_status() -> list[ProviderHealth]:
    status_by_id = {
        status.provider_id: status
        for status in provider_router.health_monitor.snapshot()
    }
    return [
        status_by_id.get(
            provider.id,
            provider_router.health_monitor.get(provider.id),
        )
        for provider in provider_router.registry.list()
    ]


@router.post("/health/{provider_id}", response_model=ProviderHealth)
async def check_provider_health(provider_id: str) -> ProviderHealth:
    provider = provider_router.registry.get(provider_id)
    if provider is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "PROVIDER_NOT_FOUND",
                "message": f"Provider '{provider_id}' is not registered",
            },
        )

    try:
        status = await provider.health_check()
    except asyncio.CancelledError:
        raise
    except Exception:
        provider_router.health_monitor.record_failure(provider_id)
        raise HTTPException(
            status_code=503,
            detail={
                "code": "PROVIDER_HEALTH_CHECK_FAILED",
                "message": "Provider health check failed",
                "provider_id": provider_id,
            },
        ) from None

    if status.availability.value == "available":
        return provider_router.health_monitor.record_success(provider_id)
    provider_router.health_monitor.record_failure(provider_id)
    raise HTTPException(
        status_code=503,
        detail={
            "code": "PROVIDER_HEALTH_CHECK_FAILED",
            "message": "Provider reported unavailable",
            "provider_id": provider_id,
        },
    )


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    try:
        return await provider_router.route(request)
    except InvalidProviderRequestError as error:
        raise HTTPException(
            status_code=400,
            detail={
                "code": error.error_code,
                "message": error.message,
            },
        ) from error
    except AllProvidersFailedError as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "ALL_PROVIDERS_FAILED",
                "message": "All eligible AI providers failed",
                "failures": [failure.model_dump() for failure in error.failures],
            },
        ) from error
