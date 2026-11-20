from abc import ABC, abstractmethod
import asyncio
import re

from backend.app.intelligence.schemas import (
    ContextRole,
    IntelligenceRequest,
    IntelligenceResponse,
    ResponseStatus,
    TaskType,
    contains_credential_content,
)
from backend.app.intelligence.adapters import (
    AdapterFailureError,
    AdapterResult,
    CapabilityAdapter,
    InvalidAdapterResultError,
)
from backend.app.intelligence.capabilities import (
    CapabilityMetadata,
    CapabilityRegistry,
    CapabilityUnavailableError,
)
from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.context import RequestContext


_PUBLIC_METADATA_TYPES = {
    "deterministic": bool,
    "native_name": str,
    "script": str,
    "direction": str,
}
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z")


def _public_metadata(result: AdapterResult) -> dict[str, bool | str]:
    metadata: dict[str, bool | str] = {}
    for key, expected_type in _PUBLIC_METADATA_TYPES.items():
        value = result.metadata.get(key)
        if type(value) is not expected_type:
            continue
        if isinstance(value, str):
            if not value.strip() or len(value) > 150:
                continue
            if _looks_credential_like(value):
                continue
            if key == "direction" and value not in {"ltr", "rtl"}:
                continue
        metadata[key] = value

    for key, value in (
        ("provider_id", result.provider_id),
        ("model_id", result.model_id),
    ):
        if value is not None and _SAFE_IDENTIFIER.fullmatch(value):
            metadata[key] = value
    return metadata


def _looks_credential_like(value: str) -> bool:
    return contains_credential_content(value)


class CentralIntelligenceCore(ABC):
    """Independent service boundary for Central Intelligence Core implementations."""

    @abstractmethod
    async def process(
        self,
        request: IntelligenceRequest,
    ) -> IntelligenceResponse:
        ...


class OrchestrationCore(CentralIntelligenceCore):
    """Deterministic coordinator for Phase 3B without HTTP or persistence."""

    def __init__(
        self,
        *,
        classifier: DeterministicTaskClassifier | None = None,
        capability_registry: CapabilityRegistry | None = None,
        adapters: dict[str, CapabilityAdapter] | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Core timeout must be positive")
        self.classifier = classifier or DeterministicTaskClassifier()
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.adapters = adapters or {}
        self.timeout_seconds = timeout_seconds

        if "text_generation" in self.adapters:
            self._register_available_capability(
                "text_generation",
                "Text Generation",
            )
        if "language_lookup" in self.adapters:
            self._register_available_capability(
                "language_lookup",
                "Language Lookup",
            )

    def _register_available_capability(
        self,
        capability_id: str,
        name: str,
    ) -> None:
        if self.capability_registry.get(capability_id) is not None:
            return
        self.capability_registry.register(CapabilityMetadata(
            capability_id=capability_id,
            name=name,
            implemented=True,
            available=True,
        ))

    async def process(
        self,
        request: IntelligenceRequest,
    ) -> IntelligenceResponse:
        try:
            validated = IntelligenceRequest.model_validate(
                request.model_dump()
            )
        except Exception:
            return IntelligenceResponse(
                task_type=TaskType.UNSUPPORTED,
                status=ResponseStatus.ERROR,
                error_code="INVALID_REQUEST",
                warnings=("The request could not be validated",),
            )

        text = next(
            (
                message.content
                for message in reversed(validated.messages)
                if message.role == ContextRole.USER
            ),
            "",
        )
        classification = self.classifier.classify(
            text,
            validated.task_type,
        )

        if classification.task_type == TaskType.UNSUPPORTED:
            return IntelligenceResponse(
                task_type=TaskType.UNSUPPORTED,
                status=ResponseStatus.UNSUPPORTED,
                error_code="UNSUPPORTED_TASK",
                warnings=(classification.reason,),
            )

        capability_id = {
            TaskType.CONVERSATION: "text_generation",
            TaskType.LANGUAGE_LOOKUP: "language_lookup",
            TaskType.PROVIDER_STATUS: "provider_status",
        }.get(classification.task_type)
        if capability_id is None:
            return IntelligenceResponse(
                task_type=TaskType.UNSUPPORTED,
                status=ResponseStatus.UNSUPPORTED,
                error_code="UNSUPPORTED_TASK",
            )

        try:
            capability = self.capability_registry.require_available(capability_id)
        except CapabilityUnavailableError:
            return IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="CAPABILITY_UNAVAILABLE",
                warnings=("The required capability is not available",),
            )

        adapter = self.adapters.get(capability_id)
        if adapter is None:
            return IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="ADAPTER_UNAVAILABLE",
                warnings=("The required adapter is not registered",),
            )

        context = RequestContext(validated.context_id)
        for message in validated.messages:
            context.add_turn(message.role, message.content)

        try:
            result = await asyncio.wait_for(
                adapter.execute(validated, context),
                timeout=self.timeout_seconds,
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            return IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="ADAPTER_TIMEOUT",
                warnings=("The capability timed out",),
            )
        except AdapterFailureError as error:
            error_code = (
                "LANGUAGE_NOT_FOUND"
                if str(error) == "LANGUAGE_NOT_FOUND"
                else "ADAPTER_FAILURE"
            )
            return IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code=error_code,
                warnings=("The capability could not complete the request",),
            )
        except InvalidAdapterResultError:
            return IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="INVALID_ADAPTER_RESULT",
                warnings=("The capability returned an invalid result",),
            )
        except Exception:
            return IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="ADAPTER_FAILURE",
                warnings=("The capability could not complete the request",),
            )

        try:
            validated_result = AdapterResult.model_validate(
                result.model_dump()
                if isinstance(result, AdapterResult)
                else result
            )
        except Exception:
            return IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="INVALID_ADAPTER_RESULT",
                warnings=("The capability returned an invalid result",),
            )

        return IntelligenceResponse(
            task_type=classification.task_type,
            status=ResponseStatus.COMPLETED,
            content=validated_result.content,
            selected_capabilities=(capability_id,),
            metadata=_public_metadata(validated_result),
        )
