from dataclasses import dataclass
import enum

from backend.app.providers.schemas import ChatResponse


class SafeProviderFailureCategory(str, enum.Enum):
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    INVALID_PROVIDER_REQUEST = "INVALID_PROVIDER_REQUEST"
    OVERALL_EXECUTION_DEADLINE = "OVERALL_EXECUTION_DEADLINE"


@dataclass(frozen=True)
class ProviderRoutingSummary:
    provider_attempt_count: int = 0
    retry_count: int = 0
    fallback_attempted: bool = False
    fallback_succeeded: bool = False
    intermediate_failure_categories: tuple[SafeProviderFailureCategory, ...] = ()


@dataclass(frozen=True)
class ProviderRoutingResult:
    response: ChatResponse
    summary: ProviderRoutingSummary
