import pytest

from backend.app.tools.contracts import (
    ExecutionIdempotencyMode,
    ExternalToolExecutionCapabilities,
)
from backend.app.tools.dispatcher import ExternalToolAdapterRegistry
from backend.app.tools.external_action_readiness import ExternalActionReadinessEvidence


class ProductionAdapter:
    production_provider = True

    @property
    def capabilities(self):
        return ExternalToolExecutionCapabilities(
            provider_id="calendar-provider",
            adapter_id="calendar-adapter",
            adapter_version="1.0.0",
            provider_scope="calendar-account-123",
            idempotency_mode=ExecutionIdempotencyMode.PROVIDER_ENFORCED,
            key_scope="account",
            idempotency_retention_seconds=86400,
            rejects_payload_mismatch=True,
            concurrent_deduplication=True,
            supports_outcome_lookup=True,
        )

    def execute(self, action):
        raise AssertionError("Registration must not execute actions")

    def lookup(self, idempotency_key):
        raise AssertionError("Registration must not query providers")


def evidence(**changes):
    values = {
        "provider_id": "calendar-provider",
        "adapter_id": "calendar-adapter",
        "adapter_version": "1.0.0",
        "provider_scope": "calendar-account-123",
        "verifier_id": "calendar-oauth-verifier-v1",
        "transport_id": "pinned-https-v1",
        "conformance_suite_id": "external-action-safety",
        "conformance_suite_version": "1.0.0",
        "provider_verification_passed": True,
        "transport_conformance_passed": True,
        "idempotency_conformance_passed": True,
        "outcome_lookup_conformance_passed": True,
    }
    values.update(changes)
    return ExternalActionReadinessEvidence(**values)


def test_production_external_adapter_requires_readiness_evidence():
    registry = ExternalToolAdapterRegistry()
    with pytest.raises(PermissionError, match="require trusted readiness"):
        registry.register("calendar.create_event", ProductionAdapter())


@pytest.mark.parametrize(
    "changes",
    [
        {"provider_id": "other-provider"},
        {"adapter_version": "2.0.0"},
        {"provider_scope": "other-account"},
        {"verifier_id": ""},
        {"transport_id": "default-http-client"},
        {"provider_verification_passed": False},
        {"transport_conformance_passed": False},
        {"idempotency_conformance_passed": False},
        {"outcome_lookup_conformance_passed": False},
    ],
)
def test_production_external_adapter_rejects_incomplete_or_mismatched_evidence(changes):
    registry = ExternalToolAdapterRegistry()
    with pytest.raises(PermissionError, match="readiness is incomplete"):
        registry.register(
            "calendar.create_event",
            ProductionAdapter(),
            readiness=evidence(**changes),
        )


def test_production_external_adapter_accepts_exact_readiness_evidence():
    registry = ExternalToolAdapterRegistry()
    adapter = ProductionAdapter()
    registry.register(
        "calendar.create_event", adapter, readiness=evidence()
    )
    assert registry.get("calendar.create_event") is adapter


def test_non_production_adapter_cannot_supply_readiness_evidence():
    registry = ExternalToolAdapterRegistry()

    class TestAdapter:
        capabilities = ProductionAdapter.capabilities.__get__(ProductionAdapter())

        def execute(self, action):
            raise AssertionError

        def lookup(self, idempotency_key):
            raise AssertionError

    with pytest.raises(ValueError, match="reserved for production"):
        registry.register(
            "calendar.create_event",
            TestAdapter(),
            readiness=evidence(),
        )



def test_production_external_adapter_requires_provider_enforced_idempotency():
    class NonIdempotentProductionAdapter(ProductionAdapter):
        @property
        def capabilities(self):
            return ExternalToolExecutionCapabilities(
                provider_id="calendar-provider",
                adapter_id="calendar-adapter",
                adapter_version="1.0.0",
                provider_scope="calendar-account-123",
                idempotency_mode=ExecutionIdempotencyMode.NONE,
                supports_outcome_lookup=True,
            )

    with pytest.raises(PermissionError, match="readiness is incomplete"):
        ExternalToolAdapterRegistry().register(
            "calendar.create_event",
            NonIdempotentProductionAdapter(),
            readiness=evidence(),
        )
