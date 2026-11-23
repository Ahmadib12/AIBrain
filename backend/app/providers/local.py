from backend.app.providers.errors import ProviderUnavailableError
from backend.app.providers.interface import AIProvider
from backend.app.providers.schemas import (
    ChatRequest,
    ChatResponse,
    ProviderAvailability,
    ProviderHealth,
)


class LocalAIProvider(AIProvider):
    """Provider interface for a future local-model runtime."""

    @property
    def id(self) -> str:
        return "local"

    @property
    def name(self) -> str:
        return "Local model runtime"

    @property
    def priority(self) -> int:
        return 0

    @property
    def enabled(self) -> bool:
        return False

    @property
    def models(self) -> tuple[str, ...]:
        return ()

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ()

    async def generate(self, request: ChatRequest) -> ChatResponse:
        raise ProviderUnavailableError(
            self.id,
            "No local model runtime is configured",
        )

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(
            provider_id=self.id,
            availability=ProviderAvailability.UNAVAILABLE,
        )
