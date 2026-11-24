"""Governed integration catalog for trusted, server-configured connectors.

The catalog is metadata and contract governance only. It does not load adapters,
store provider credentials, or perform network requests. Integrations must be
registered by application code and expose READ_ONLY contracts in this layer.
"""
import copy
import re
from dataclasses import dataclass
from typing import Any

from backend.app.tools.contracts import (
    ToolContract,
    ToolRisk,
    contract_fingerprint,
)

_INTEGRATION_ID = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_SCOPE = re.compile(r"^[a-z][a-z0-9_.:-]{1,95}$")


@dataclass(frozen=True)
class IntegrationTool:
    """One read-only tool and the exact owner-granted scopes it requires."""

    contract: ToolContract
    required_scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.contract, ToolContract):
            raise TypeError("Integration tools require a ToolContract")
        if self.contract.risk is not ToolRisk.READ_ONLY:
            raise ValueError("M10 integrations accept read-only tools only")
        if not isinstance(self.required_scopes, tuple):
            raise ValueError("required_scopes must be a tuple")
        if len(set(self.required_scopes)) != len(self.required_scopes):
            raise ValueError("Integration scopes must be unique")
        if any(
            not isinstance(scope, str) or not _SCOPE.fullmatch(scope)
            for scope in self.required_scopes
        ):
            raise ValueError("Integration scope identifier is invalid")


@dataclass(frozen=True)
class IntegrationManifest:
    integration_id: str
    name: str
    description: str
    version: str
    tools: tuple[IntegrationTool, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.integration_id, str) or not _INTEGRATION_ID.fullmatch(
            self.integration_id
        ):
            raise ValueError("Integration ID must be a stable lowercase identifier")
        for field_name in ("name", "description", "version"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{field_name} must contain 1 to 256 characters")
        if not isinstance(self.tools, tuple) or not self.tools:
            raise ValueError("An integration must declare at least one tool")
        if any(not isinstance(item, IntegrationTool) for item in self.tools):
            raise TypeError("Integration manifest contains an invalid tool")
        tool_ids = [item.contract.tool_id for item in self.tools]
        if len(set(tool_ids)) != len(tool_ids):
            raise ValueError("Integration tool IDs must be unique")
        for item in self.tools:
            if not item.contract.tool_id.startswith(self.integration_id + "."):
                raise ValueError("Tool IDs must be namespaced by integration ID")


class IntegrationRegistry:
    """Application-owned allowlist of connector manifests.

    Callers cannot submit manifests or adapter objects through an API. A
    registry instance is populated only by trusted application composition.
    """

    def __init__(self) -> None:
        self._integrations: dict[str, IntegrationManifest] = {}
        self._tools: dict[str, tuple[str, IntegrationTool]] = {}

    def register(self, manifest: IntegrationManifest) -> None:
        if not isinstance(manifest, IntegrationManifest):
            raise TypeError("A validated IntegrationManifest is required")
        if manifest.integration_id in self._integrations:
            raise ValueError("Integration is already registered")
        for item in manifest.tools:
            tool_id = item.contract.tool_id
            if tool_id in self._tools:
                raise ValueError("Integration tool is already registered")
        snapshot = copy.deepcopy(manifest)
        self._integrations[snapshot.integration_id] = snapshot
        for item in snapshot.tools:
            self._tools[item.contract.tool_id] = (
                snapshot.integration_id,
                item,
            )

    def get(self, integration_id: str) -> IntegrationManifest | None:
        manifest = self._integrations.get(integration_id)
        return copy.deepcopy(manifest) if manifest is not None else None

    def list(self) -> tuple[IntegrationManifest, ...]:
        return tuple(
            copy.deepcopy(self._integrations[key])
            for key in sorted(self._integrations)
        )

    def resolve_tool(self, tool_id: str) -> tuple[str, IntegrationTool] | None:
        value = self._tools.get(tool_id)
        return copy.deepcopy(value) if value is not None else None

    def catalog(self) -> list[dict[str, Any]]:
        """Return safe public metadata; never expose adapter or credential state."""
        result = []
        for manifest in self.list():
            result.append({
                "integration_id": manifest.integration_id,
                "name": manifest.name,
                "description": manifest.description,
                "version": manifest.version,
                "tools": [
                    {
                        "tool_id": item.contract.tool_id,
                        "name": item.contract.name,
                        "description": item.contract.description,
                        "risk": item.contract.risk.value,
                        "required_scopes": list(item.required_scopes),
                        "contract_fingerprint": contract_fingerprint(item.contract),
                    }
                    for item in manifest.tools
                ],
            })
        return result
