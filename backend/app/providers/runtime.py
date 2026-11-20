from backend.app.config import Settings
from backend.app.providers.fallback import FallbackExecutor
from backend.app.providers.health import ProviderHealthMonitor
from backend.app.providers.mock import MockAIProvider
from backend.app.providers.registry import ProviderRegistry
from backend.app.providers.router import ModelRouter


def build_provider_router(settings: Settings) -> ModelRouter:
    registry = ProviderRegistry()
    health_monitor = ProviderHealthMonitor()

    priorities = {}
    for item in settings.provider_priorities.split(","):
        if ":" not in item:
            continue
        provider_id, priority = item.rsplit(":", 1)
        try:
            priorities[provider_id.strip()] = int(priority)
        except ValueError:
            continue

    mock_priority = priorities.get("mock", 100)
    mock_provider = MockAIProvider(
        enabled=settings.mock_provider_enabled,
        priority=mock_priority,
        simulate_failure=settings.mock_provider_simulate_failure,
    )
    registry.register(mock_provider)

    fallback = FallbackExecutor(
        health_monitor=health_monitor,
        timeout_seconds=settings.provider_timeout_seconds,
        max_attempts=settings.provider_max_attempts,
    )
    return ModelRouter(
        registry,
        health_monitor,
        fallback,
        fallback_enabled=settings.fallback_enabled,
    )
