from abc import ABC, abstractmethod

from backend.app.providers.schemas import (
    ChatRequest,
    ChatResponse,
    ProviderHealth,
)


class AIProvider(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def priority(self) -> int:
        ...

    @property
    @abstractmethod
    def enabled(self) -> bool:
        ...

    @property
    @abstractmethod
    def models(self) -> tuple[str, ...]:
        ...

    @property
    @abstractmethod
    def capabilities(self) -> tuple[str, ...]:
        ...

    @abstractmethod
    async def generate(self, request: ChatRequest) -> ChatResponse:
        ...

    @abstractmethod
    async def health_check(self) -> ProviderHealth:
        ...
