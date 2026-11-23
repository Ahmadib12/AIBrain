from datetime import datetime, timedelta, timezone

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository


CHECKS = {
    "stable_idempotency_key",
    "payload_mismatch_rejected",
    "concurrent_deduplication",
    "timeout_after_acceptance_lookup",
    "timeout_before_acceptance_proven",
    "ambiguous_lookup_stays_unknown",
    "lookup_never_dispatches",
    "sanitized_provider_output",
    "binding_change_rejected",
    "no_provider_fallback",
}
CAPABILITIES = {
    "idempotency_mode": "provider_enforced",
    "key_scope": "provider-account-and-operation",
    "idempotency_retention_seconds": 86400,
    "rejects_payload_mismatch": True,
    "concurrent_deduplication": True,
    "supports_outcome_lookup": True,
}


@pytest.fixture
def repository(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'certification.db'}")
    yield ToolRequestRepository(database)
    database.close()


def certify(repository, **overrides):
    values = {
        "provider_id": "provider-x",
        "adapter_id": "adapter-x",
        "adapter_version": "1.2.3",
        "provider_scope": "account-42",
        "tool_id": "send-message",
        "tool_contract_fingerprint": "b" * 64,
        "capabilities": CAPABILITIES,
        "test_suite_version": "conformance-v1",
        "conformance_results": {name: True for name in CHECKS},
        "test_report_sha256": "a" * 64,
        "evidence_references": ["sandbox://provider-x/report-42"],
        "approved_by": "security-reviewer",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    }
    values.update(overrides)
    return repository.certify_external_adapter(**values)


def lookup(repository, **overrides):
    values = {
        "provider_id": "provider-x",
        "adapter_id": "adapter-x",
        "adapter_version": "1.2.3",
        "provider_scope": "account-42",
        "tool_id": "send-message",
        "tool_contract_fingerprint": "b" * 64,
        "capabilities": CAPABILITIES,
    }
    values.update(overrides)
    return repository.get_active_external_adapter_certification(**values)


def test_matching_approved_certification_is_active(repository):
    certificate = certify(repository)
    active = lookup(repository)

    assert active is not None
    assert active["id"] == certificate["id"]
    assert active["conformance_results"] == {name: True for name in CHECKS}
    assert active["test_report_sha256"] == "a" * 64


@pytest.mark.parametrize(
    "change",
    [
        {"provider_id": "other-provider"},
        {"adapter_id": "other-adapter"},
        {"adapter_version": "9.9.9"},
        {"provider_scope": "other-account"},
        {"tool_id": "delete-account"},
        {"tool_contract_fingerprint": "c" * 64},
        {"capabilities": {**CAPABILITIES, "supports_outcome_lookup": False}},
    ],
)
def test_certification_does_not_transfer_to_different_binding(repository, change):
    certify(repository)
    assert lookup(repository, **change) is None


def test_revoked_certification_is_not_active(repository):
    certificate = certify(repository)
    repository.revoke_external_adapter_certification(
        certificate["id"],
        revoked_by="security-reviewer",
        reason="Provider sandbox credentials were compromised",
    )

    assert lookup(repository) is None
    with pytest.raises(PermissionError, match="already revoked"):
        repository.revoke_external_adapter_certification(
            certificate["id"],
            revoked_by="security-reviewer",
            reason="Duplicate revocation",
        )


def test_expired_certification_is_rejected(repository):
    certificate = certify(repository)
    repository.database.connect().execute(
        "UPDATE external_adapter_certifications SET expires_at = ? WHERE id = ?",
        (
            (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            certificate["id"],
        ),
    )
