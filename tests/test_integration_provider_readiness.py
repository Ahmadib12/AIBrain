import pytest

from backend.app.tools.integration_provider_readiness import (
    ProviderReadinessEvidence,
    ProviderReadinessGate,
)
from backend.app.tools.integration_runtime import IntegrationAdapterRegistry


class ProductionReadAdapter:
    production_provider = True

    async def execute(self, *, user_id, connection_id, tool_id, arguments):
        return {"items": []}


def _evidence(**changes):
    values = {
        "integration_id": "catalog",
        "verifier_id": "catalog-oauth-verifier-v1",
        "transport_id": "pinned-https-v1",
        "conformance_suite_version": "m10.11-m10.13",
        "verified_scopes": ("catalog.read",),
        "provider_verification_passed": True,
        "transport_conformance_passed": True,
    }
    values.update(changes)
    return ProviderReadinessEvidence(**values)


def test_production_adapter_registration_requires_complete_readiness():
    registry = IntegrationAdapterRegistry()
    with pytest.raises(PermissionError, match="requires readiness evidence"):
        registry.register("catalog", ProductionReadAdapter())


@pytest.mark.parametrize(
    "changes",
    [
        {"integration_id": "other"},
        {"verifier_id": ""},
        {"transport_id": "requests-default"},
        {"conformance_suite_version": "old"},
        {"verified_scopes": ()},
        {"provider_verification_passed": False},
        {"transport_conformance_passed": False},
    ],
)
def test_production_adapter_registration_fails_closed_on_incomplete_evidence(changes):
    registry = IntegrationAdapterRegistry()
    with pytest.raises(PermissionError, match="readiness is incomplete"):
        registry.register(
            "catalog", ProductionReadAdapter(), readiness=_evidence(**changes)
        )


def test_production_adapter_registration_accepts_complete_trusted_evidence():
    registry = IntegrationAdapterRegistry()
    adapter = ProductionReadAdapter()
    registry.register("catalog", adapter, readiness=_evidence())
    assert registry.get("catalog") is adapter


def test_test_adapter_does_not_accept_production_readiness_evidence():
    registry = IntegrationAdapterRegistry()

    class TestAdapter:
        async def execute(self, *, user_id, connection_id, tool_id, arguments):
            return {"items": []}

    with pytest.raises(ValueError, match="reserved for production"):
        registry.register("catalog", TestAdapter(), readiness=_evidence())
