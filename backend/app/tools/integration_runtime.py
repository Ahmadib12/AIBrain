"""Bounded read-only runtime for trusted integration adapters.

Adapters are installed only by application composition. They receive opaque
connection identifiers, never bearer credentials or caller-selected URLs.
A concrete adapter must obtain secrets from its own injected secure vault.
"""
import asyncio
import json
from typing import Any, Protocol, runtime_checkable

from backend.app.persistence.integration_connections import IntegrationConnectionRepository
from backend.app.tools.contracts import ToolRisk
from backend.app.tools.integrations import IntegrationRegistry
from backend.app.tools.integration_provider_readiness import (
    ProviderReadinessEvidence,
    ProviderReadinessGate,
)
from backend.app.tools.validation import validate_tool_arguments


_SENSITIVE_KEYS = {
    "access_token", "refresh_token", "authorization", "password",
    "client_secret", "private_key", "api_key", "credential", "secret",
    "token", "id_token", "cookie", "set_cookie",
}


@runtime_checkable
class ReadOnlyIntegrationAdapter(Protocol):
    async def execute(
        self,
        *,
        user_id: str,
        connection_id: str,
        tool_id: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute one bounded read using adapter-owned secure dependencies."""
        ...


class IntegrationAdapterRegistry:
    """Trusted adapter allowlist; never populated from request data."""

    def __init__(self) -> None:
        self._adapters: dict[str, ReadOnlyIntegrationAdapter] = {}

    def register(
        self,
        integration_id: str,
        adapter: ReadOnlyIntegrationAdapter,
        *,
        readiness: ProviderReadinessEvidence | None = None,
    ) -> None:
        if not isinstance(integration_id, str) or not integration_id.strip():
            raise ValueError("Integration ID is invalid")
        if not isinstance(adapter, ReadOnlyIntegrationAdapter):
            raise TypeError("A conforming read-only integration adapter is required")
        if getattr(adapter, "production_provider", False) is True:
            ProviderReadinessGate.validate(integration_id, readiness)
        elif readiness is not None:
            raise ValueError("Readiness evidence is reserved for production provider adapters")
        if integration_id in self._adapters:
            raise ValueError("An adapter is already registered for this integration")
        self._adapters[integration_id] = adapter

    def get(self, integration_id: str) -> ReadOnlyIntegrationAdapter | None:
        return self._adapters.get(integration_id)


def _reject_sensitive_output(value: Any, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError("Adapter output nesting exceeds the safety limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Adapter output keys must be strings")
            normalized_key = key.lower().replace("-", "_").replace(" ", "_")
            compact_key = normalized_key.replace("_", "")
            if normalized_key in _SENSITIVE_KEYS or compact_key in {
                "accesstoken", "refreshtoken", "authorization",
                "clientsecret", "privatekey", "apikey", "credential",
                "password", "secret", "cookie", "setcookie",
            }:
                raise ValueError("Adapter output contains a credential-like field")
            _reject_sensitive_output(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            raise ValueError("Adapter output collection exceeds the safety limit")
        for item in value:
            _reject_sensitive_output(item, depth + 1)


class ReadOnlyIntegrationRuntime:
    def __init__(
        self,
        *,
        manifests: IntegrationRegistry,
        adapters: IntegrationAdapterRegistry,
        connections: IntegrationConnectionRepository,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 65_536,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("Integration timeout must be between 0 and 60 seconds")
        if max_output_bytes < 1 or max_output_bytes > 1_048_576:
            raise ValueError("Integration output bound is invalid")
        self.manifests = manifests
        self.adapters = adapters
        self.connections = connections
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    async def execute(
        self,
        user_id: str,
        connection_id: str,
        tool_id: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        resolved = self.manifests.resolve_tool(tool_id)
        if resolved is None:
            raise LookupError("Integration tool is not registered")
        integration_id, item = resolved
        contract = item.contract
        if contract.risk is not ToolRisk.READ_ONLY:
            raise PermissionError("Integration runtime permits read-only tools only")
        validate_tool_arguments(contract.input_schema, arguments)
        if not self.connections.has_active_grants(
            user_id, connection_id, integration_id, item.required_scopes
        ):
            raise PermissionError("An active owner connection and exact scope grants are required")
        # Recheck immediately before dispatch. This narrows the race window;
        # a request already in flight is not retroactively cancelled by revoke.
        if not self.connections.has_active_grants(
            user_id, connection_id, integration_id, item.required_scopes
        ):
            raise PermissionError("Integration authority changed before dispatch")
        adapter = self.adapters.get(integration_id)
        if adapter is None:
            raise PermissionError("No trusted adapter is registered for this integration")

        # The adapter receives an opaque connection ID, not secret material.
        # Concrete adapters must use an independently managed encrypted vault.
        result = await asyncio.wait_for(
            adapter.execute(
                user_id=user_id,
                connection_id=connection_id,
                tool_id=tool_id,
                arguments=dict(arguments),
            ),
            timeout=self.timeout_seconds,
        )
        # Discard results if owner authority was revoked or expired in flight.
        if not self.connections.has_active_grants(
            user_id, connection_id, integration_id, item.required_scopes
        ):
            raise PermissionError("Integration authority changed during execution")
        if not isinstance(result, dict):
            raise ValueError("Integration adapter must return an object")
        _reject_sensitive_output(result)
        validate_tool_arguments(contract.output_schema, result)
        encoded = json.dumps(
            result, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > self.max_output_bytes:
            raise ValueError("Integration adapter output exceeds the configured limit")
        return result
