from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
)
from backend.app.providers.fallback import FallbackExecutor
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.registry import ProviderRegistry
from backend.app.providers.schemas import ChatRequest, ChatResponse


class ModelRouter:
    def __init__(
        self,
        registry: ProviderRegistry,
        health_monitor: ProviderHealthMonitor,
        fallback_executor: FallbackExecutor,
        *,
        fallback_enabled: bool = True,
    ) -> None:
        self.registry = registry
        self.health_monitor = health_monitor
        self.fallback_executor = fallback_executor
        self.fallback_enabled = fallback_enabled

    async def route(self, request: ChatRequest) -> ChatResponse:
        if request.provider:
            provider = self.registry.get(request.provider)
            if provider is None:
                raise InvalidProviderRequestError(
                    request.provider,
                    f"Unknown provider '{request.provider}'",
                )
            if not provider.enabled:
                raise InvalidProviderRequestError(
                    provider.id,
                    f"Provider '{provider.id}' is disabled",
                )
            if not request.allow_fallback or not self.fallback_enabled:
                candidates = [provider]
            else:
                candidates = [provider]
                candidates.extend(
                    alternative
                    for alternative in self.registry.enabled()
                    if alternative.id != provider.id
                    and self.health_monitor.is_available(alternative.id)
                    and (
                        request.model is None
                        or request.model in alternative.models
                    )
                )
        else:
            eligible = [
                provider
                for provider in self.registry.enabled()
                if self.health_monitor.is_available(provider.id)
                and (request.model is None or request.model in provider.models)
            ]
            if not eligible:
                raise AllProvidersFailedError([])
            if request.allow_fallback and self.fallback_enabled:
                candidates = eligible
            else:
                candidates = [eligible[0]]

        if not candidates:
            raise AllProvidersFailedError([])

        return await self.fallback_executor.execute(
            candidates,
            request,
        )
