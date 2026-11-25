from backend.app.providers.errors import (
    AllProvidersFailedError,
    InvalidProviderRequestError,
)
from backend.app.providers.fallback import FallbackExecutor
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.registry import ProviderRegistry
from backend.app.providers.schemas import ChatRequest, ChatResponse
from backend.app.providers.routing import ProviderRoutingResult
from backend.app.providers.policy import (
    ProviderRoutingPolicy,
    ProviderRoutingRequirements,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.app.intelligence.context import ExecutionState


class ModelRouter:
    def __init__(
        self,
        registry: ProviderRegistry,
        health_monitor: ProviderHealthMonitor,
        fallback_executor: FallbackExecutor,
        *,
        fallback_enabled: bool = True,
        provider_policy: ProviderRoutingPolicy | None = None,
    ) -> None:
        self.registry = registry
        self.health_monitor = health_monitor
        self.fallback_executor = fallback_executor
        self.fallback_enabled = fallback_enabled
        self.provider_policy = provider_policy

    async def route(
        self,
        request: ChatRequest,
        *,
        requirements: ProviderRoutingRequirements | None = None,
    ) -> ChatResponse:
        result = await self.route_with_outcome(request, requirements=requirements)
        return result.response

    async def route_with_outcome(
        self,
        request: ChatRequest,
        execution_state: "ExecutionState | None" = None,
        *,
        requirements: ProviderRoutingRequirements | None = None,
    ) -> ProviderRoutingResult:
        if request.provider:
            provider = self.registry.get(request.provider)
            if provider is None:
                raise InvalidProviderRequestError(
                    request.provider,
                    f"Unknown provider '{request.provider}'",
                    source="caller",
                )
            if not provider.enabled:
                raise InvalidProviderRequestError(
                    provider.id,
                    f"Provider '{provider.id}' is disabled",
                    source="caller",
                )
            if request.model is not None and request.model not in provider.models:
                raise InvalidProviderRequestError(
                    provider.id,
                    f"Unknown model '{request.model}'",
                    source="caller",
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
                if request.model is not None:
                    raise InvalidProviderRequestError(
                        "model",
                        f"Unknown model '{request.model}'",
                        source="caller",
                    )
                raise AllProvidersFailedError([])
            if request.allow_fallback and self.fallback_enabled:
                candidates = eligible
            else:
                candidates = [eligible[0]]

        if requirements is not None:
            if self.provider_policy is None:
                raise PermissionError(
                    "Provider routing requirements need a trusted provider policy"
                )
            candidates = list(
                self.provider_policy.filter_candidates(candidates, requirements)
            )
            if not candidates:
                raise PermissionError(
                    "No registered provider satisfies the trusted data and capability policy"
                )

        if not candidates:
            raise AllProvidersFailedError([])

        return await self.fallback_executor.execute_with_outcome(
            candidates,
            request,
            execution_state,
        )
