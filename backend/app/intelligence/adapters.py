import asyncio
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.agli.core import AGLI
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.schemas import IntelligenceRequest
from backend.app.providers.router import ModelRouter
from backend.app.providers.schemas import ChatMessage, ChatRequest


class AdapterFailureError(RuntimeError):
    pass


class InvalidAdapterResultError(RuntimeError):
    pass


class AdapterResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=100_000)
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=20)
    provider_id: str | None = Field(default=None, max_length=100)
    model_id: str | None = Field(default=None, max_length=200)


class CapabilityAdapter(ABC):
    @abstractmethod
    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        ...


class ProviderRoutingAdapter(CapabilityAdapter):
    def __init__(self, router: ModelRouter) -> None:
        self.router = router

    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        messages = [
            ChatMessage(role=message.role.value, content=message.content)
            for message in request.messages
        ]
        provider_request = ChatRequest(
            messages=messages,
            task_type="general",
            model=request.model,
            provider=request.provider,
            allow_fallback=request.allow_fallback,
        )
        try:
            response = await self.router.route(provider_request)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise AdapterFailureError("Provider routing failed") from error
        if not response.content or not response.content.strip():
            raise InvalidAdapterResultError("Provider returned an empty result")
        return AdapterResult(
            content=response.content,
            metadata={
                "deterministic": bool(response.metadata.get("deterministic", False))
            },
            provider_id=response.provider_id,
            model_id=response.model_id,
        )


class AGLILanguageAdapter(CapabilityAdapter):
    def __init__(self, agli: AGLI) -> None:
        self.agli = agli

    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        if not request.language_code:
            raise InvalidAdapterResultError(
                "A language code is required"
            )
        try:
            language = self.agli.lookup(request.language_code)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise AdapterFailureError("Language lookup failed") from error
        if language is None:
            raise AdapterFailureError("LANGUAGE_NOT_FOUND")
        return AdapterResult(
            content=f"{language.name} ({language.code})",
            metadata={
                "native_name": language.native_name,
                "script": language.script.code,
                "direction": language.script.direction,
            },
        )
