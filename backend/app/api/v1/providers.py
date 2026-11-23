import asyncio

from fastapi import APIRouter, Depends, HTTPException
from backend.app.concurrency import require_ai_capacity
from backend.app.auth.operator import require_provider_operator

from backend.app.config import get_settings
from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
    OverallExecutionDeadlineError,
    ProviderHealthTimeoutError,
    ProviderHealthUnavailableError,
)
from backend.app.providers.runtime import build_provider_router
from backend.app.providers.schemas import (
    ChatRequest,
    ChatResponse,
    ProviderHealth,
    ProviderInfo,
)


router = APIRouter(prefix="/providers", tags=["providers"])
provider_router = build_provider_router(get_settings())


@router.get("", response_model=list[ProviderInfo])
async def list_providers(
    _operator: None = Depends(require_provider_operator),
) -> list[ProviderInfo]:
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
async def provider_status(
    _operator: None = Depends(require_provider_operator),
) -> list[ProviderHealth]:
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
async def check_provider_health(
    provider_id: str,
    _operator: None = Depends(require_provider_operator),
) -> ProviderHealth:
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
        return await provider_router.health_monitor.check_health(
            provider_id,
            provider.health_check,
            timeout_seconds=(
                get_settings().provider_health_check_timeout_seconds
            ),
        )
    except asyncio.CancelledError:
        raise
    except ProviderHealthTimeoutError:
        raise HTTPException(
            status_code=504,
            detail={
                "code": "PROVIDER_HEALTH_TIMEOUT",
                "message": "Provider health check timed out",
                "provider_id": provider_id,
            },
        ) from None
    except ProviderHealthUnavailableError:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "PROVIDER_HEALTH_CHECK_FAILED",
                "message": "Provider reported unavailable",
                "provider_id": provider_id,
            },
        ) from None
    except Exception:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "PROVIDER_HEALTH_CHECK_FAILED",
                "message": "Provider health check failed",
                "provider_id": provider_id,
            },
        ) from None


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    _capacity: None = Depends(require_ai_capacity, scope='request'),
) -> ChatResponse:
    try:
        return await provider_router.route(request)
    except OverallExecutionDeadlineError:
        raise HTTPException(
            status_code=504,
            detail={
                "code": "REQUEST_TIMEOUT",
                "message": "The overall execution deadline was exhausted",
            },
        ) from None
    except InvalidProviderRequestError as error:
        raise HTTPException(
            status_code=400,
            detail={
                "code": error.error_code,
                "message": "Invalid provider or model selection",
            },
        ) from error
    except AllProvidersFailedError:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "ALL_PROVIDERS_FAILED",
                "message": "All eligible AI providers failed",
            },
        ) from None
