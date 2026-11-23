from abc import ABC, abstractmethod


class LanguageProcessingEngine(ABC):
    @property
    @abstractmethod
    def engine_id(self) -> str:
        ...

    @abstractmethod
    async def detect_language(self, text: str) -> dict:
        raise NotImplementedError

    @abstractmethod
    async def translate(
        self,
        text: str,
        *,
        source_language: str,
        target_language: str,
    ) -> dict:
        raise NotImplementedError
