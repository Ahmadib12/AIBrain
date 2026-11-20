import asyncio
import time

from backend.app.providers.errors import (
    InvalidProviderRequestError,
    ProviderUnavailableError,
)
from backend.app.providers.interface import AIProvider
from backend.app.providers.schemas import (
    ChatRequest,
    ChatResponse,
    ProviderAvailability,
    ProviderHealth,
)


class MockAIProvider(AIProvider):
    def __init__(
        self,
        *,
        enabled: bool = True,
        priority: int = 100,
        simulate_failure: bool = False,
    ) -> None:
        self._enabled = enabled
        self._priority = priority
        self._simulate_failure = simulate_failure
        self.fail_health_check = False

    @property
    def id(self) -> str:
        return "mock"

    @property
    def name(self) -> str:
        return "Deterministic Mock Provider"

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def models(self) -> tuple[str, ...]:
        return ("mock-chat-v1",)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text_generation", "chat_completion")

    def set_simulated_failure(self, enabled: bool) -> None:
        self._simulate_failure = enabled

    async def generate(self, request: ChatRequest) -> ChatResponse:
        started = time.perf_counter()
        await asyncio.sleep(0)

        if self._simulate_failure:
            raise ProviderUnavailableError(
                self.id,
                "Mock provider is configured to simulate failure",
            )

        last_user_message = next(
            (
                message.content
                for message in reversed(request.messages)
                if message.role == "user"
            ),
            "",
        )
        latency_ms = (time.perf_counter() - started) * 1000
        model_id = request.model or self.models[0]
        if model_id not in self.models:
            raise InvalidProviderRequestError(
                self.id,
                f"Unknown mock provider model '{model_id}'",
            )

        return ChatResponse(
            content=f"[mock response] {last_user_message}",
            provider_id=self.id,
            model_id=model_id,
            latency_ms=latency_ms,
            metadata={"deterministic": True},
        )

    async def health_check(self) -> ProviderHealth:
        await asyncio.sleep(0)
        if self.fail_health_check:
            return ProviderHealth(
                provider_id=self.id,
                availability=ProviderAvailability.UNAVAILABLE,
            )
        return ProviderHealth(
            provider_id=self.id,
            availability=ProviderAvailability.AVAILABLE,
        )
