from backend.app.agli.core import AGLI
from backend.app.agli.registry import language_registry
from backend.app.api.v1.providers import provider_router
from backend.app.intelligence.adapters import (
    AGLILanguageAdapter,
    CapabilityAdapter,
    ProviderRoutingAdapter,
)
from backend.app.intelligence.core import OrchestrationCore


def get_intelligence_core() -> OrchestrationCore:
    adapters: dict[str, CapabilityAdapter] = {}

    has_available_provider = any(
        provider.enabled
        and provider_router.health_monitor.is_available(provider.id)
        for provider in provider_router.registry.list()
    )
    if has_available_provider:
        adapters["text_generation"] = ProviderRoutingAdapter(provider_router)

    agli = AGLI(language_registry)
    if agli.list_languages():
        adapters["language_lookup"] = AGLILanguageAdapter(agli)

    return OrchestrationCore(adapters=adapters)
