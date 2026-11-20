"""Central Intelligence Core foundation."""

from backend.app.intelligence.capabilities import (
    CapabilityRegistry,
    CapabilityUnavailableError,
    DuplicateCapabilityError,
)
from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.core import CentralIntelligenceCore
from backend.app.intelligence.core import OrchestrationCore
from backend.app.intelligence.adapters import (
    AGLILanguageAdapter,
    AdapterFailureError,
    AdapterResult,
    CapabilityAdapter,
    InvalidAdapterResultError,
    ProviderRoutingAdapter,
)

__all__ = [
    "CapabilityRegistry",
    "CapabilityUnavailableError",
    "DuplicateCapabilityError",
    "DeterministicTaskClassifier",
    "RequestContext",
    "CentralIntelligenceCore",
    "OrchestrationCore",
    "AGLILanguageAdapter",
    "AdapterFailureError",
    "AdapterResult",
    "CapabilityAdapter",
    "InvalidAdapterResultError",
    "ProviderRoutingAdapter",
]
