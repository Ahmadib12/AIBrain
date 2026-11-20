import pytest

from backend.app.intelligence.capabilities import (
    CapabilityRegistry,
    CapabilityUnavailableError,
    DuplicateCapabilityError,
)
from backend.app.intelligence.schemas import (
    CapabilityMetadata,
    CapabilityStatus,
)


def test_register_and_lookup_capability() -> None:
    registry = CapabilityRegistry()
    capability = CapabilityMetadata(
        capability_id="language_lookup",
        name="Language Lookup",
    )

    registry.register(capability)

    assert registry.get("language_lookup") is capability
    assert registry.get("missing") is None


def test_duplicate_capability_rejected() -> None:
    registry = CapabilityRegistry()
    capability = CapabilityMetadata(
        capability_id="language_lookup",
        name="Language Lookup",
    )
    registry.register(capability)

    with pytest.raises(DuplicateCapabilityError):
        registry.register(capability)


def test_capability_status_distinguishes_operational_levels() -> None:
    registered = CapabilityMetadata(
        capability_id="language_lookup",
        name="Language Lookup",
    )
    implemented = CapabilityMetadata(
        capability_id="text_generation",
        name="Text Generation",
        implemented=True,
    )
    available = CapabilityMetadata(
        capability_id="mock_chat",
        name="Mock Chat",
        implemented=True,
        available=True,
    )

    assert registered.status == CapabilityStatus.REGISTERED
    assert implemented.status == CapabilityStatus.IMPLEMENTED
    assert available.status == CapabilityStatus.AVAILABLE


def test_available_requires_implemented() -> None:
    with pytest.raises(ValueError, match="Available capabilities"):
        CapabilityMetadata(
            capability_id="invalid",
            name="Invalid",
            implemented=False,
            available=True,
        )


def test_registered_false_is_rejected() -> None:
    with pytest.raises(ValueError, match="registered=True"):
        CapabilityMetadata(
            capability_id="invalid",
            name="Invalid",
            registered=False,
        )


def test_registry_filters_implemented_and_available() -> None:
    registry = CapabilityRegistry()
    registry.register(CapabilityMetadata(
        capability_id="registered",
        name="Registered",
    ))
    registry.register(CapabilityMetadata(
        capability_id="implemented",
        name="Implemented",
        implemented=True,
    ))
    registry.register(CapabilityMetadata(
        capability_id="available",
        name="Available",
        implemented=True,
        available=True,
    ))

    assert {item.capability_id for item in registry.implemented()} == {
        "implemented",
        "available",
    }
    assert {item.capability_id for item in registry.available()} == {"available"}


def test_unavailable_capability_cannot_be_required_as_executable() -> None:
    registry = CapabilityRegistry()
    registry.register(CapabilityMetadata(
        capability_id="registered_only",
        name="Registered Only",
    ))
    registry.register(CapabilityMetadata(
        capability_id="implemented_only",
        name="Implemented Only",
        implemented=True,
    ))

    with pytest.raises(CapabilityUnavailableError, match="not available"):
        registry.require_available("registered_only")
    with pytest.raises(CapabilityUnavailableError, match="not available"):
        registry.require_available("implemented_only")


def test_available_capability_can_be_required() -> None:
    registry = CapabilityRegistry()
    registry.register(CapabilityMetadata(
        capability_id="mock_chat",
        name="Mock Chat",
        implemented=True,
        available=True,
    ))

    capability = registry.require_available("mock_chat")

    assert capability.capability_id == "mock_chat"
