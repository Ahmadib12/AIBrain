import asyncio

import pytest
from pydantic import ValidationError

from backend.app.providers.interface import AIProvider
from backend.app.providers.policy import (
    ProviderDataClass,
    ProviderExecutionLocation,
    ProviderProfile,
    ProviderProfileRegistry,
    ProviderRoutingPolicy,
    ProviderRoutingRequirements,
)
from backend.app.providers.router import ModelRouter
from backend.app.providers.registry import ProviderRegistry
from backend.app.providers.routing import ProviderRoutingResult, ProviderRoutingSummary
from backend.app.providers.schemas import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ProviderAvailability,
    ProviderHealth,
)


class StubProvider(AIProvider):
    def __init__(self, provider_id, capabilities=("text_generation",)):
        self._id = provider_id
        self._capabilities = capabilities

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._id

    @property
    def priority(self):
        return 10

    @property
    def enabled(self):
        return True

    @property
    def models(self):
        return ("test-model",)

    @property
    def capabilities(self):
        return self._capabilities

    async def generate(self, request):
        return ChatResponse(
            content="ok",
            provider_id=self.id,
            model_id="test-model",
            latency_ms=1,
        )

    async def health_check(self):
        return ProviderHealth(
            provider_id=self.id,
            availability=ProviderAvailability.AVAILABLE,
        )


class Healthy:
    def is_available(self, provider_id):
        return True


class CaptureFallback:
    async def execute_with_outcome(self, candidates, request, execution_state):
        provider = candidates[0]
        return ProviderRoutingResult(
            response=ChatResponse(
                content="ok",
                provider_id=provider.id,
                model_id="test-model",
                latency_ms=1,
            ),
            summary=ProviderRoutingSummary(provider_attempt_count=1),
        )


def request(provider):
    return ChatRequest(
        messages=[ChatMessage(role="user", content="hello")],
        provider=provider,
        model="test-model",
        allow_fallback=False,
    )


def profile(provider_id, location, classes, *, capabilities=("text_generation",), cost=1):
    return ProviderProfile(
        provider_id=provider_id,
        execution_location=location,
        data_classifications=classes,
        capabilities=capabilities,
        cost_tier=cost,
        data_residency="local-device" if location == ProviderExecutionLocation.LOCAL else "provider-region",
        provider_version="1.0.0",
    )


def test_sensitive_request_is_routed_only_to_trusted_local_profile():
    local = StubProvider("local")
    cloud = StubProvider("cloud")
    registry = ProviderProfileRegistry()
    registry.register(profile(
        "local",
        ProviderExecutionLocation.LOCAL,
        (ProviderDataClass.PUBLIC, ProviderDataClass.CONFIDENTIAL, ProviderDataClass.SENSITIVE),
    ))
    registry.register(profile(
        "cloud",
        ProviderExecutionLocation.CLOUD,
        (ProviderDataClass.PUBLIC,),
    ))
    provider_registry = ProviderRegistry()
    provider_registry.register(local)
    provider_registry.register(cloud)
    router = ModelRouter(
        provider_registry,
        Healthy(),
        CaptureFallback(),
        provider_policy=ProviderRoutingPolicy(registry),
    )

    result = asyncio.run(router.route_with_outcome(
        request("local"),
        requirements=ProviderRoutingRequirements(
            data_classification=ProviderDataClass.SENSITIVE,
            allowed_locations=(ProviderExecutionLocation.LOCAL,),
            required_capabilities=("text_generation",),
            max_cost_tier=2,
        ),
    ))
    assert result.response.provider_id == "local"


def test_provider_without_trusted_profile_is_not_eligible_for_policy_routing():
    provider = StubProvider("unprofiled")
    registry = ProviderRegistry()
    registry.register(provider)
    router = ModelRouter(registry, Healthy(), CaptureFallback(), provider_policy=ProviderRoutingPolicy(ProviderProfileRegistry()))
    with pytest.raises(PermissionError, match="No registered provider"):
        asyncio.run(router.route_with_outcome(
            request("unprofiled"),
            requirements=ProviderRoutingRequirements(
                data_classification=ProviderDataClass.SENSITIVE,
                allowed_locations=(ProviderExecutionLocation.LOCAL,),
            ),
        ))


def test_policy_routing_fails_closed_without_trusted_policy():
    registry = ProviderRegistry()
    registry.register(StubProvider("cloud"))
    router = ModelRouter(registry, Healthy(), CaptureFallback())
    with pytest.raises(PermissionError, match="trusted provider policy"):
        asyncio.run(router.route_with_outcome(
            request("cloud"),
            requirements=ProviderRoutingRequirements(),
        ))


def test_provider_profile_rejects_unknown_fields_and_empty_locations():
    with pytest.raises(ValidationError):
        ProviderProfile(
            provider_id="bad",
            execution_location="cloud",
            data_classifications=("public",),
            capabilities=(),
            cost_tier=1,
            data_residency="unknown",
            provider_version="1.0",
            credential="not-allowed",
        )
    with pytest.raises(ValidationError):
        ProviderRoutingRequirements(allowed_locations=())



def test_provider_policy_enforces_data_residency_allowlist():
    provider = StubProvider("region-a")
    profiles = ProviderProfileRegistry()
    profiles.register(profile(
        "region-a",
        ProviderExecutionLocation.CLOUD,
        (ProviderDataClass.PUBLIC,),
    ))
    registry = ProviderRegistry()
    registry.register(provider)
    router = ModelRouter(
        registry, Healthy(), CaptureFallback(),
        provider_policy=ProviderRoutingPolicy(profiles),
    )
    with pytest.raises(PermissionError, match="No registered provider"):
        asyncio.run(router.route_with_outcome(
            request("region-a"),
            requirements=ProviderRoutingRequirements(
                data_classification=ProviderDataClass.PUBLIC,
                allowed_locations=(ProviderExecutionLocation.CLOUD,),
                allowed_data_residencies=("region-b",),
            ),
        ))
