from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TraceTaskType(str, Enum):
    CONVERSATION = "conversation"
    LANGUAGE_LOOKUP = "language_lookup"
    PROVIDER_STATUS = "provider_status"
    UNSUPPORTED = "unsupported"


class TraceClassificationStatus(str, Enum):
    EXPLICIT = "explicit"
    DEFAULT = "default"
    UNSUPPORTED = "unsupported"


class ClassificationReasonCode(str, Enum):
    NOT_CLASSIFIED = "not_classified"
    EXPLICIT_TASK = "explicit_task"
    EXPLICIT_UNSUPPORTED_TASK = "explicit_unsupported_task"
    UNKNOWN_EXPLICIT_TASK = "unknown_explicit_task"
    EMPTY_INPUT = "empty_input"
    UNSUPPORTED_ACTION = "unsupported_action"
    PROVIDER_STATUS_TERMS = "provider_status_terms"
    LANGUAGE_METADATA_TERMS = "language_metadata_terms"
    DEFAULT_CONVERSATION = "default_conversation"
    OTHER = "other"


class CapabilityId(str, Enum):
    TEXT_GENERATION = "text_generation"
    LANGUAGE_LOOKUP = "language_lookup"
    PROVIDER_STATUS = "provider_status"


class DecisionReasonCode(str, Enum):
    REQUEST_VALIDATION_FAILED = "request_validation_failed"
    CORE_EXECUTION_FAILED = "core_execution_failed"
    UNSUPPORTED_CLASSIFICATION = "unsupported_classification"
    NO_CAPABILITY_MAPPING = "no_capability_mapping"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    ADAPTER_UNAVAILABLE = "adapter_unavailable"
    CAPABILITY_SELECTED = "capability_selected"


class ProviderFailureCategory(str, Enum):
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    INVALID_PROVIDER_REQUEST = "INVALID_PROVIDER_REQUEST"
    OVERALL_EXECUTION_DEADLINE = "OVERALL_EXECUTION_DEADLINE"


class TraceExecutionStatus(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    UNSUPPORTED = "unsupported"


class TraceErrorCode(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    UNSUPPORTED_TASK = "UNSUPPORTED_TASK"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    ADAPTER_UNAVAILABLE = "ADAPTER_UNAVAILABLE"
    ADAPTER_TIMEOUT = "ADAPTER_TIMEOUT"
    ADAPTER_FAILURE = "ADAPTER_FAILURE"
    INVALID_ADAPTER_RESULT = "INVALID_ADAPTER_RESULT"
    LANGUAGE_NOT_FOUND = "LANGUAGE_NOT_FOUND"
    INTELLIGENCE_FAILURE = "INTELLIGENCE_FAILURE"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    INVALID_PROVIDER_REQUEST = "INVALID_PROVIDER_REQUEST"
    ALL_PROVIDERS_FAILED = "ALL_PROVIDERS_FAILED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"


class DecisionTrace(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    trace_id: UUID
    task_type: TraceTaskType | None
    classification_status: TraceClassificationStatus | None
    classification_reason_code: ClassificationReasonCode
    considered_capability: CapabilityId | None
    selected_capability: CapabilityId | None
    capability_available: bool | None
    decision_reason_code: DecisionReasonCode
    execution_status: TraceExecutionStatus
    error_code: TraceErrorCode | None
    fallback_attempted: bool = False
    fallback_succeeded: bool = False
    retry_count: int = Field(default=0, ge=0)
    provider_attempt_count: int = Field(default=0, ge=0)
    intermediate_failure_categories: tuple[ProviderFailureCategory, ...] = ()


_TASK_TYPES = {
    item.value: item
    for item in TraceTaskType
}
_CLASSIFICATION_STATUSES = {
    item.value: item
    for item in TraceClassificationStatus
}
_CAPABILITY_IDS = {
    item.value: item
    for item in CapabilityId
}
_ERROR_CODES = {
    item.value: item
    for item in TraceErrorCode
}
_PROVIDER_FAILURE_CATEGORIES = {
    item.value: item
    for item in ProviderFailureCategory
}
_CLASSIFICATION_REASONS = {
    "Task type was explicitly selected": ClassificationReasonCode.EXPLICIT_TASK,
    "The requested task is explicitly unsupported": (
        ClassificationReasonCode.EXPLICIT_UNSUPPORTED_TASK
    ),
    "No input text was provided": ClassificationReasonCode.EMPTY_INPUT,
    "The request appears to require an unsupported consequential action": (
        ClassificationReasonCode.UNSUPPORTED_ACTION
    ),
    "Text matches provider status terminology": (
        ClassificationReasonCode.PROVIDER_STATUS_TERMS
    ),
    "Text matches language metadata terminology": (
        ClassificationReasonCode.LANGUAGE_METADATA_TERMS
    ),
    "No capability-specific terms were matched; classified conservatively": (
        ClassificationReasonCode.DEFAULT_CONVERSATION
    ),
}


class DecisionTraceBuilder:
    """Builds a safe trace projection from controlled orchestration decisions."""

    def __init__(self) -> None:
        self.task_type: TraceTaskType | None = None
        self.classification_status: TraceClassificationStatus | None = None
        self.classification_reason_code = ClassificationReasonCode.NOT_CLASSIFIED
        self.considered_capability: CapabilityId | None = None
        self.selected_capability: CapabilityId | None = None
        self.capability_available: bool | None = None
        self.decision_reason_code = DecisionReasonCode.REQUEST_VALIDATION_FAILED
        self.fallback_attempted = False
        self.fallback_succeeded = False
        self.retry_count = 0
        self.provider_attempt_count = 0
        self.intermediate_failure_categories: tuple[
            ProviderFailureCategory,
            ...,
        ] = ()

    def record_classification(
        self,
        task_type: str,
        status: str,
        reason: str,
    ) -> None:
        self.task_type = _TASK_TYPES.get(task_type)
        self.classification_status = _CLASSIFICATION_STATUSES.get(status)
        self.classification_reason_code = _CLASSIFICATION_REASONS.get(
            reason,
            (
                ClassificationReasonCode.UNKNOWN_EXPLICIT_TASK
                if reason.startswith("Unknown explicit task type:")
                else ClassificationReasonCode.OTHER
            ),
        )

    def record_considered_capability(self, capability_id: str) -> None:
        self.considered_capability = _CAPABILITY_IDS.get(capability_id)

    def record_capability_availability(self, available: bool) -> None:
        self.capability_available = available

    def record_selected_capability(self, capability_id: str) -> None:
        self.selected_capability = _CAPABILITY_IDS.get(capability_id)

    def record_routing_summary(self, summary) -> None:
        self.fallback_attempted = bool(summary.fallback_attempted)
        self.fallback_succeeded = bool(summary.fallback_succeeded)
        self.retry_count = max(0, int(summary.retry_count))
        self.provider_attempt_count = max(
            0,
            int(summary.provider_attempt_count),
        )
        categories = []
        for category in summary.intermediate_failure_categories:
            value = (
                category.value
                if hasattr(category, "value")
                else str(category)
            )
            safe_category = _PROVIDER_FAILURE_CATEGORIES.get(value)
            if safe_category is not None:
                categories.append(safe_category)
        self.intermediate_failure_categories = tuple(categories)

    def record_decision_reason(self, reason: DecisionReasonCode) -> None:
        self.decision_reason_code = reason

    def build(
        self,
        *,
        request_id: str,
        response_status: str,
        error_code: str | None,
    ) -> DecisionTrace:
        safe_error_code = _ERROR_CODES.get(error_code)
        if response_status == "unsupported":
            execution_status = TraceExecutionStatus.UNSUPPORTED
        elif response_status == "completed":
            execution_status = TraceExecutionStatus.SUCCEEDED
        elif error_code in {
            TraceErrorCode.ADAPTER_TIMEOUT.value,
            TraceErrorCode.REQUEST_TIMEOUT.value,
            TraceErrorCode.PROVIDER_TIMEOUT.value,
        }:
            execution_status = TraceExecutionStatus.TIMED_OUT
        elif error_code in {
            TraceErrorCode.INVALID_REQUEST.value,
            TraceErrorCode.CAPABILITY_UNAVAILABLE.value,
            TraceErrorCode.ADAPTER_UNAVAILABLE.value,
            TraceErrorCode.INVALID_PROVIDER_REQUEST.value,
        }:
            execution_status = TraceExecutionStatus.NOT_ATTEMPTED
        elif response_status == "error":
            execution_status = TraceExecutionStatus.FAILED
        else:
            execution_status = TraceExecutionStatus.NOT_ATTEMPTED

        return DecisionTrace(
            trace_id=UUID(request_id),
            task_type=self.task_type,
            classification_status=self.classification_status,
            classification_reason_code=self.classification_reason_code,
            considered_capability=self.considered_capability,
            selected_capability=self.selected_capability,
            capability_available=self.capability_available,
            decision_reason_code=self.decision_reason_code,
            execution_status=execution_status,
            error_code=safe_error_code,
            fallback_attempted=self.fallback_attempted,
            fallback_succeeded=self.fallback_succeeded,
            retry_count=self.retry_count,
            provider_attempt_count=self.provider_attempt_count,
            intermediate_failure_categories=(
                self.intermediate_failure_categories
            ),
        )
