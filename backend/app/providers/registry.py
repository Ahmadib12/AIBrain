from backend.app.providers.errors import DuplicateProviderError
from backend.app.providers.interface import AIProvider


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, AIProvider] = {}

    def register(self, provider: AIProvider) -> None:
        if provider.id in self._providers:
            raise DuplicateProviderError(
                f"Provider '{provider.id}' is already registered"
            )
        self._providers[provider.id] = provider

    def unregister(self, provider_id: str) -> None:
        self._providers.pop(provider_id, None)

    def get(self, provider_id: str) -> AIProvider | None:
        return self._providers.get(provider_id)

    def list(self) -> tuple[AIProvider, ...]:
        return tuple(sorted(
            self._providers.values(),
            key=lambda provider: (-provider.priority, provider.id),
        ))

    def enabled(self) -> tuple[AIProvider, ...]:
        return tuple(provider for provider in self.list() if provider.enabled)
