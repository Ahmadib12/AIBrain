from abc import ABC, abstractmethod
import asyncio
from collections.abc import Callable
import logging
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
    ProviderRoutingAdapter,
    ProviderRoutingAdapterError,
)
from backend.app.intelligence.capabilities import (
    CapabilityMetadata,
    CapabilityRegistry,
    CapabilityUnavailableError,
)
from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.context import ExecutionState, RequestContext
from backend.app.intelligence.planning.engine import PlanningEngine
from backend.app.intelligence.trace import (
    DecisionReasonCode,
    DecisionTraceBuilder,
)


_PUBLIC_METADATA_TYPES = {
    "deterministic": bool,
    "native_name": str,
    "script": str,
    "direction": str,
}
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z")


def _task_is_cancelled() -> bool:
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


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
        planning_engine: PlanningEngine | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Core timeout must be positive")
        self.classifier = classifier or DeterministicTaskClassifier()
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.adapters = adapters or {}
        self.planning_engine = planning_engine or PlanningEngine()
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
        trace: DecisionTraceBuilder | None
        trace_recording_failed = False
        planning_payload: dict | None = None
        try:
            trace = DecisionTraceBuilder()
        except Exception:
            trace = None
            trace_recording_failed = True
            logging.getLogger("aibrain.intelligence").warning(
                "Decision trace recording failed"
            )

        def record_trace(
            record: Callable[[DecisionTraceBuilder], None],
        ) -> None:
            nonlocal trace_recording_failed
            if trace is None or trace_recording_failed:
                return
            try:
                record(trace)
            except Exception:
                trace_recording_failed = True
                logging.getLogger("aibrain.intelligence").warning(
                    "Decision trace recording failed"
                )

        def finish(response: IntelligenceResponse) -> IntelligenceResponse:
            nonlocal trace_recording_failed
            if planning_payload is not None:
                response = response.model_copy(
                    update={"planning": planning_payload}
                )
            if trace is None or trace_recording_failed:
                return response
            try:
                decision_trace = trace.build(
                    request_id=response.request_id,
                    response_status=response.status.value,
                    error_code=response.error_code,
                )
                return response.model_copy(
                    update={"decision_trace": decision_trace}
                )
            except Exception:
                trace_recording_failed = True
                logging.getLogger("aibrain.intelligence").warning(
                    "Decision trace recording failed"
                )
                return response

        try:
            validated = IntelligenceRequest.model_validate(
                request.model_dump()
            )
        except Exception:
            return finish(IntelligenceResponse(
                task_type=TaskType.UNSUPPORTED,
                status=ResponseStatus.ERROR,
                error_code="INVALID_REQUEST",
                warnings=("The request could not be validated",),
            ))

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
        record_trace(
            lambda builder: builder.record_classification(
                classification.task_type.value,
                classification.status.value,
                classification.reason,
            )
        )

        try:
            planning = self.planning_engine.plan(
                text,
                classification,
                available_capabilities=(
                    capability.capability_id
                    for capability in self.capability_registry.available()
                    if capability.capability_id in self.adapters
                ),
            )
            planning_payload = planning.model_dump(mode="json")
        except Exception:
            # Planning is advisory; a planning defect must not bypass or alter
            # the existing classifier, capability, adapter, or authorization
            # boundaries. Keep the failure private and continue safely.
            logging.getLogger("aibrain.intelligence").warning(
                "Request planning failed"
            )

        if classification.task_type == TaskType.UNSUPPORTED:
            record_trace(
                lambda builder: builder.record_decision_reason(
                    DecisionReasonCode.UNSUPPORTED_CLASSIFICATION
                )
            )
            return finish(IntelligenceResponse(
                task_type=TaskType.UNSUPPORTED,
                status=ResponseStatus.UNSUPPORTED,
                error_code="UNSUPPORTED_TASK",
                warnings=(classification.reason,),
            ))

        capability_id = {
            TaskType.CONVERSATION: "text_generation",
            TaskType.LANGUAGE_LOOKUP: "language_lookup",
            TaskType.PROVIDER_STATUS: "provider_status",
        }.get(classification.task_type)
        if capability_id is None:
            record_trace(
                lambda builder: builder.record_decision_reason(
                    DecisionReasonCode.NO_CAPABILITY_MAPPING
                )
            )
            return finish(IntelligenceResponse(
                task_type=TaskType.UNSUPPORTED,
                status=ResponseStatus.UNSUPPORTED,
                error_code="UNSUPPORTED_TASK",
            ))

        record_trace(
            lambda builder: builder.record_considered_capability(capability_id)
        )
        try:
            capability = self.capability_registry.require_available(capability_id)
        except CapabilityUnavailableError:
            record_trace(
                lambda builder: builder.record_capability_availability(False)
            )
            record_trace(
                lambda builder: builder.record_decision_reason(
                    DecisionReasonCode.CAPABILITY_UNAVAILABLE
                )
            )
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="CAPABILITY_UNAVAILABLE",
                warnings=("The required capability is not available",),
            ))
        record_trace(
            lambda builder: builder.record_capability_availability(True)
        )

        adapter = self.adapters.get(capability_id)
        if adapter is None:
            record_trace(
                lambda builder: builder.record_decision_reason(
                    DecisionReasonCode.ADAPTER_UNAVAILABLE
                )
            )
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="ADAPTER_UNAVAILABLE",
                warnings=("The required adapter is not registered",),
            ))
        record_trace(
            lambda builder: builder.record_selected_capability(capability_id)
        )
        record_trace(
            lambda builder: builder.record_decision_reason(
                DecisionReasonCode.CAPABILITY_SELECTED
            )
        )

        loop = asyncio.get_running_loop()
        execution_state = ExecutionState(
            deadline=loop.time() + self.timeout_seconds,
        )
        context = RequestContext(
            validated.context_id,
            execution_state=execution_state,
        )
        for message in validated.messages:
            context.add_turn(message.role, message.content)

        def record_routing_summary() -> None:
            if context.routing_summary is None:
                return
            record_trace(
                lambda builder: builder.record_routing_summary(
                    context.routing_summary,
                )
            )

        try:
            remaining_budget = execution_state.remaining_budget(loop)
            if remaining_budget <= 0:
                record_routing_summary()
                return finish(IntelligenceResponse(
                    task_type=classification.task_type,
                    status=ResponseStatus.ERROR,
                    error_code="REQUEST_TIMEOUT",
                    warnings=("The overall execution deadline was exhausted",),
                ))
            result = await asyncio.wait_for(
                adapter.execute(validated, context),
                timeout=remaining_budget,
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            if _task_is_cancelled():
                raise
            if isinstance(adapter, ProviderRoutingAdapter):
                record_routing_summary()
                return finish(IntelligenceResponse(
                    task_type=classification.task_type,
                    status=ResponseStatus.ERROR,
                    error_code="REQUEST_TIMEOUT",
                    warnings=("The overall execution deadline was exhausted",),
                ))
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="ADAPTER_TIMEOUT",
                warnings=("The capability timed out",),
            ))
        except ProviderRoutingAdapterError as error:
            record_routing_summary()
            category = error.category
            if category == "INVALID_PROVIDER_REQUEST":
                return finish(IntelligenceResponse(
                    task_type=classification.task_type,
                    status=ResponseStatus.ERROR,
                    error_code="INVALID_PROVIDER_REQUEST",
                    warnings=("The provider or model selection is invalid",),
                ))
            if category == "REQUEST_TIMEOUT":
                return finish(IntelligenceResponse(
                    task_type=classification.task_type,
                    status=ResponseStatus.ERROR,
                    error_code="REQUEST_TIMEOUT",
                    warnings=("The overall execution deadline was exhausted",),
                ))
            if category == "PROVIDER_TIMEOUT":
                return finish(IntelligenceResponse(
                    task_type=classification.task_type,
                    status=ResponseStatus.ERROR,
                    error_code="PROVIDER_TIMEOUT",
                    warnings=("The provider requests timed out",),
                ))
            if category == "PROVIDER_FAILURE":
                return finish(IntelligenceResponse(
                    task_type=classification.task_type,
                    status=ResponseStatus.ERROR,
                    error_code="PROVIDER_FAILURE",
                    warnings=("A provider could not complete the request",),
                ))
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="ALL_PROVIDERS_FAILED",
                warnings=("All eligible providers failed",),
            ))
        except AdapterFailureError as error:
            error_code = (
                "LANGUAGE_NOT_FOUND"
                if str(error) == "LANGUAGE_NOT_FOUND"
                else "ADAPTER_FAILURE"
            )
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code=error_code,
                warnings=("The capability could not complete the request",),
            ))
        except InvalidAdapterResultError:
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="INVALID_ADAPTER_RESULT",
                warnings=("The capability returned an invalid result",),
            ))
        except Exception:
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="ADAPTER_FAILURE",
                warnings=("The capability could not complete the request",),
            ))

        try:
            validated_result = AdapterResult.model_validate(
                result.model_dump()
                if isinstance(result, AdapterResult)
                else result
            )
        except Exception:
            return finish(IntelligenceResponse(
                task_type=classification.task_type,
                status=ResponseStatus.ERROR,
                error_code="INVALID_ADAPTER_RESULT",
                warnings=("The capability returned an invalid result",),
            ))

        record_routing_summary()
        return finish(IntelligenceResponse(
            task_type=classification.task_type,
            status=ResponseStatus.COMPLETED,
            content=validated_result.content,
            selected_capabilities=(capability_id,),
            metadata=_public_metadata(validated_result),
        ))
