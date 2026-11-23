import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.tools.conformance import REQUIRED_CHECKS, verify_evidence_manifest


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


def evidence():
    artifacts = {
        "sandbox-report.json": json.dumps(
            {"runner": "sandbox-suite", "summary": "all required checks passed"},
            sort_keys=True,
        ).encode(),
        "execution-trace.bin": b"deterministic sandbox trace\x00\x01",
    }
    now = datetime.now(timezone.utc)
    manifest = {
        "schema_version": "aibrain-conformance-evidence-v1",
        "provider_id": "provider-x",
        "adapter_id": "adapter-x",
        "adapter_version": "1.2.3",
        "provider_scope": "account-42",
        "tool_id": "send-message",
        "tool_contract_fingerprint": "b" * 64,
        "capabilities": CAPABILITIES,
        "test_suite_version": "conformance-v1",
        "sandbox_environment": "provider-x-sandbox-region-1",
        "executed_at": (now - timedelta(minutes=2)).isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(),
        "tests": {
            name: {"status": "passed", "artifact": (
                "sandbox-report.json" if index % 2 == 0 else "execution-trace.bin"
            )}
            for index, name in enumerate(sorted(REQUIRED_CHECKS))
        },
        "artifacts": {
            name: hashlib.sha256(content).hexdigest()
            for name, content in artifacts.items()
        },
    }
    return manifest, artifacts


def verify(repository, manifest=None, artifacts=None):
    default_manifest, default_artifacts = evidence()
    return repository.verify_external_adapter_evidence(
        manifest or default_manifest,
        artifacts or default_artifacts,
    )


def certify(repository, **overrides):
    package = verify(repository)
    values = {
        "evidence_package_id": package["id"],
        "approved_by": "security-reviewer",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
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


def test_manifest_verification_persists_real_artifact_bytes(repository):
    manifest, artifacts = evidence()
    package = repository.verify_external_adapter_evidence(manifest, artifacts)

    assert package["manifest_sha256"] == hashlib.sha256(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    assert package["artifacts"]["sandbox-report.json"]["content"] == artifacts["sandbox-report.json"]
    assert package["provenance"] == "unattested"


@pytest.mark.parametrize("mutation", ["tamper", "missing", "extra"])
def test_artifact_tampering_or_set_mismatch_is_rejected(repository, mutation):
    manifest, artifacts = evidence()
    if mutation == "tamper":
        artifacts["sandbox-report.json"] += b"tampered"
    elif mutation == "missing":
        del artifacts["execution-trace.bin"]
    else:
        artifacts["unexpected.bin"] = b"extra"
    with pytest.raises(ValueError):
        repository.verify_external_adapter_evidence(manifest, artifacts)


def test_manifest_rejects_missing_failed_unknown_or_unreferenced_tests(repository):
    manifest, artifacts = evidence()
    del manifest["tests"]["lookup_never_dispatches"]
    with pytest.raises(ValueError, match="exact required"):
        verify_evidence_manifest(manifest, artifacts)

    manifest, artifacts = evidence()
    manifest["tests"]["lookup_never_dispatches"]["status"] = "failed"
    with pytest.raises(ValueError, match="ungrounded"):
        verify_evidence_manifest(manifest, artifacts)

    manifest, artifacts = evidence()
    manifest["tests"]["lookup_never_dispatches"]["artifact"] = "missing.bin"
    with pytest.raises(ValueError, match="ungrounded"):
        verify_evidence_manifest(manifest, artifacts)


def test_expired_and_future_dated_evidence_is_rejected(repository):
    manifest, artifacts = evidence()
    manifest["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError, match="future-dated, expired"):
        repository.verify_external_adapter_evidence(manifest, artifacts)

    manifest, artifacts = evidence()
    manifest["executed_at"] = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    with pytest.raises(ValueError, match="future-dated"):
        repository.verify_external_adapter_evidence(manifest, artifacts)


def test_canonical_manifest_rejects_unknown_fields_and_wrong_contract(repository):
    manifest, artifacts = evidence()
    manifest["unrecognized"] = "must fail closed"
    with pytest.raises(ValueError, match="incomplete or unknown"):
        repository.verify_external_adapter_evidence(manifest, artifacts)

    manifest, artifacts = evidence()
    manifest["tool_contract_fingerprint"] = "not-a-digest"
    with pytest.raises(ValueError, match="fingerprint"):
        repository.verify_external_adapter_evidence(manifest, artifacts)


def test_matching_approved_certification_is_active(repository):
    certificate = certify(repository)
    active = lookup(repository)

    assert active is not None
    assert active["id"] == certificate["id"]
    assert active["conformance_results"] == {name: True for name in REQUIRED_CHECKS}
    package = repository.get_external_adapter_evidence_package(
        certificate["evidence_references"][0].split(":", 1)[1]
    )
    assert certificate["test_report_sha256"] == package["manifest_sha256"]


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
        certificate["id"], revoked_by="security-reviewer",
        reason="Provider sandbox credentials were compromised",
    )
    assert lookup(repository) is None
    with pytest.raises(PermissionError, match="already revoked"):
        repository.revoke_external_adapter_certification(
            certificate["id"], revoked_by="security-reviewer",
            reason="Duplicate revocation",
        )


def test_certification_cannot_outlive_evidence_package(repository):
    package = verify(repository)
    with pytest.raises(ValueError, match="outlive"):
        repository.certify_external_adapter(
            evidence_package_id=package["id"],
            approved_by="security-reviewer",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        )


def test_certification_requires_existing_verified_package(repository):
    with pytest.raises(LookupError, match="not found"):
        repository.certify_external_adapter(
            evidence_package_id="unknown-package",
            approved_by="security-reviewer",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        )


def test_certification_rejects_missing_operator(repository):
    package = verify(repository)
    with pytest.raises(ValueError, match="operator"):
        repository.certify_external_adapter(
            evidence_package_id=package["id"],
            approved_by=" ",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        )


def test_legacy_unverified_certification_arguments_are_no_longer_accepted(repository):
    with pytest.raises(TypeError):
        repository.certify_external_adapter(
            provider_id="provider-x",
            adapter_id="adapter-x",
            adapter_version="1.2.3",
            provider_scope="account-42",
            tool_id="send-message",
            tool_contract_fingerprint="b" * 64,
            capabilities=CAPABILITIES,
            test_suite_version="conformance-v1",
            conformance_results={name: True for name in REQUIRED_CHECKS},
            test_report_sha256="a" * 64,
            evidence_references=["sandbox://fake"],
            approved_by="security-reviewer",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        )
