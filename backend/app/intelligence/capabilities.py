from backend.app.intelligence.schemas import CapabilityMetadata


class DuplicateCapabilityError(ValueError):
    pass


class CapabilityUnavailableError(RuntimeError):
    pass


class CapabilityRegistry:
    def __init__(self) -> None:
        self._capabilities: dict[str, CapabilityMetadata] = {}

    def register(self, capability: CapabilityMetadata) -> None:
        if capability.capability_id in self._capabilities:
            raise DuplicateCapabilityError(
                f"Capability '{capability.capability_id}' is already registered"
            )
        self._capabilities[capability.capability_id] = capability

    def get(self, capability_id: str) -> CapabilityMetadata | None:
        return self._capabilities.get(capability_id.lower())

    def list(self) -> tuple[CapabilityMetadata, ...]:
        return tuple(
            sorted(
                self._capabilities.values(),
                key=lambda capability: capability.capability_id,
            )
        )

    def implemented(self) -> tuple[CapabilityMetadata, ...]:
        return tuple(
            capability
            for capability in self.list()
            if capability.implemented
        )

    def available(self) -> tuple[CapabilityMetadata, ...]:
        return tuple(
            capability
            for capability in self.list()
            if capability.available
        )

    def require_available(self, capability_id: str) -> CapabilityMetadata:
        capability = self.get(capability_id)
        if capability is None:
            raise CapabilityUnavailableError(
                f"Capability '{capability_id}' is not registered"
            )
        if not capability.available:
            raise CapabilityUnavailableError(
                f"Capability '{capability_id}' is not available"
            )
        return capability
