import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.tools.attestation import (
    build_attestation_payload, generate_test_keypair, sign_attestation_for_runner,
)
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



def runner_scope(package):
    return {
        "provider_id": package["provider_id"],
        "adapter_id": package["adapter_id"],
        "adapter_version": package["adapter_version"],
        "provider_scope": package["provider_scope"],
        "tool_id": package["tool_id"],
    }

def certify(repository, **overrides):
    package = verify(repository)
    public_key, private_key = generate_test_keypair()
    now = datetime.now(timezone.utc)
    key_id = "runner-key-" + package["id"]
    repository.register_trusted_runner_key(
        key_id=key_id,
        runner_id="trusted-sandbox-runner",
        **runner_scope(package),
        public_key=public_key,
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=30)).isoformat(),
        registered_by="security-admin",
    )
    issued_at = now.isoformat()
    attestation_expires = min(
        datetime.fromisoformat(package["expires_at"]),
        now + timedelta(hours=20),
    ).isoformat()
    payload = build_attestation_payload(
        package_id=package["id"],
        manifest_sha256=package["manifest_sha256"],
        artifact_hashes=package["artifact_hashes"],
        runner_id="trusted-sandbox-runner",
        provider_id=package["provider_id"],
        adapter_id=package["adapter_id"],
        adapter_version=package["adapter_version"],
        provider_scope=package["provider_scope"],
        sandbox_environment=package["sandbox_environment"],
        nonce="nonce_" + package["id"].replace("-", ""),
        issued_at=issued_at,
        expires_at=attestation_expires,
    )
    signature = sign_attestation_for_runner(private_key, payload)
    repository.attest_external_adapter_evidence(
        package["id"], key_id=key_id, runner_id="trusted-sandbox-runner",
        nonce=payload["nonce"], issued_at=issued_at,
        expires_at=attestation_expires, signature=signature,
    )
    values = {
        "evidence_package_id": package["id"],
        "approved_by": "security-reviewer",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
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
    assert package["provenance"] == "runner_attested"
    with pytest.raises(PermissionError, match="already been certified"):
        repository.certify_external_adapter(
            evidence_package_id=package["id"],
            approved_by="second-reviewer",
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        )


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



def test_active_certification_fails_closed_if_persisted_artifact_is_tampered(repository):
    certificate = certify(repository)
    package_id = certificate["evidence_references"][0].split(":", 1)[1]
    connection = repository.database.connect()
    connection.execute(
        "DROP TRIGGER prevent_external_adapter_evidence_artifact_update"
    )
    connection.execute(
        """
        UPDATE external_adapter_evidence_artifacts
        SET content = ?
        WHERE package_id = ? AND artifact_name = ?
        """,
        (b"tampered after verification", package_id, "sandbox-report.json"),
    )
    connection.commit()

    assert lookup(repository) is None


def test_verified_evidence_records_are_immutable(repository):
    package = verify(repository)
    connection = repository.database.connect()
    with pytest.raises(Exception):
        connection.execute(
            "UPDATE external_adapter_evidence_packages SET provenance = 'provider_signed' WHERE id = ?",
            (package["id"],),
        )
    connection.rollback()


def test_certification_cannot_outlive_evidence_package(repository):
    with pytest.raises(ValueError, match="outlive"):
        certify(
            repository,
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



def test_attestation_signature_binds_manifest_and_scope(repository):
    package = verify(repository)
    public_key, private_key = generate_test_keypair()
    now = datetime.now(timezone.utc)
    key_id = "runner-key-binding"
    repository.register_trusted_runner_key(
        key_id=key_id, runner_id="runner-a", **runner_scope(package), public_key=public_key,
        valid_from=(now - timedelta(minutes=1)).isoformat(),
        valid_until=(now + timedelta(days=1)).isoformat(),
        registered_by="security-admin",
    )
    payload = build_attestation_payload(
        package_id=package["id"], manifest_sha256=package["manifest_sha256"],
        artifact_hashes=package["artifact_hashes"], runner_id="runner-a",
        provider_id=package["provider_id"], adapter_id=package["adapter_id"],
        adapter_version=package["adapter_version"],
        provider_scope=package["provider_scope"],
        sandbox_environment=package["sandbox_environment"],
        nonce="nonce_" + "x" * 32,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )
    payload["provider_scope"] = "attacker-account"
    signature = sign_attestation_for_runner(private_key, payload)
    with pytest.raises(PermissionError, match="signature"):
        repository.attest_external_adapter_evidence(
            package["id"], key_id=key_id, runner_id="runner-a",
            nonce=payload["nonce"], issued_at=payload["issued_at"],
            expires_at=payload["expires_at"], signature=signature,
        )


def test_runner_signing_key_cannot_attest_outside_registered_provider_scope(repository):
    manifest, artifacts = evidence()
    first_package = repository.verify_external_adapter_evidence(manifest, artifacts)
    other_manifest = json.loads(json.dumps(manifest))
    other_manifest["provider_id"] = "provider-y"
    other_package = repository.verify_external_adapter_evidence(other_manifest, artifacts)

    public_key, _ = generate_test_keypair()
    now = datetime.now(timezone.utc)
    repository.register_trusted_runner_key(
        key_id="provider-scoped-key",
        runner_id="provider-x-runner",
        **runner_scope(first_package),
        public_key=public_key,
        valid_from=(now - timedelta(minutes=1)).isoformat(),
        valid_until=(now + timedelta(days=1)).isoformat(),
        registered_by="security-admin",
    )
    with pytest.raises(PermissionError, match="outside the trusted runner key scope"):
        repository.build_external_adapter_evidence_attestation_payload(
            other_package["id"],
            key_id="provider-scoped-key",
            runner_id="provider-x-runner",
            nonce="nonce_" + "p" * 32,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )


def test_attestation_nonce_and_package_cannot_be_replayed(repository):
    package = verify(repository)
    public_key, private_key = generate_test_keypair()
    now = datetime.now(timezone.utc)
    key_id = "runner-key-replay"
    repository.register_trusted_runner_key(
        key_id=key_id, runner_id="runner-replay", **runner_scope(package), public_key=public_key,
        valid_from=(now - timedelta(minutes=1)).isoformat(),
        valid_until=(now + timedelta(days=1)).isoformat(),
        registered_by="security-admin",
    )
    payload = build_attestation_payload(
        package_id=package["id"], manifest_sha256=package["manifest_sha256"],
        artifact_hashes=package["artifact_hashes"], runner_id="runner-replay",
        provider_id=package["provider_id"], adapter_id=package["adapter_id"],
        adapter_version=package["adapter_version"],
        provider_scope=package["provider_scope"],
        sandbox_environment=package["sandbox_environment"],
        nonce="nonce_" + "y" * 32, issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )
    signature = sign_attestation_for_runner(private_key, payload)
    kwargs = {
        "key_id": key_id, "runner_id": "runner-replay",
        "nonce": payload["nonce"], "issued_at": payload["issued_at"],
        "expires_at": payload["expires_at"], "signature": signature,
    }
    repository.attest_external_adapter_evidence(package["id"], **kwargs)
    with pytest.raises(PermissionError, match="already has"):
        repository.attest_external_adapter_evidence(package["id"], **kwargs)


def test_revoked_runner_key_invalidates_existing_certification(repository):
    certificate = certify(repository)
    package_id = certificate["evidence_references"][0].split(":", 1)[1]
    attestation = repository.get_external_adapter_evidence_attestation(package_id)
    repository.revoke_trusted_runner_key(
        attestation["key_id"], revoked_by="security-admin",
        reason="Runner signing key compromise",
    )
    assert lookup(repository) is None
    assert repository.get_external_adapter_evidence_package(package_id)["provenance"] == "runner_attestation_revoked"
    with pytest.raises(PermissionError, match="already revoked"):
        repository.revoke_trusted_runner_key(
            attestation["key_id"], revoked_by="security-admin",
            reason="Duplicate revocation",
        )


def test_certification_requires_trusted_runner_attestation(repository):
    package = verify(repository)
    with pytest.raises(PermissionError, match="attestation is required"):
        repository.certify_external_adapter(
            evidence_package_id=package["id"], approved_by="security-reviewer",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        )



def test_runner_identity_must_match_registered_key(repository):
    package = verify(repository)
    public_key, _ = generate_test_keypair()
    now = datetime.now(timezone.utc)
    repository.register_trusted_runner_key(
        key_id="runner-key-identity", runner_id="approved-runner",
        **runner_scope(package), public_key=public_key,
        valid_from=(now - timedelta(minutes=1)).isoformat(),
        valid_until=(now + timedelta(days=1)).isoformat(),
        registered_by="security-admin",
    )
    with pytest.raises(PermissionError, match="does not match"):
        repository.attest_external_adapter_evidence(
            package["id"], key_id="runner-key-identity",
            runner_id="different-runner", nonce="nonce_" + "z" * 32,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
            signature="invalid-signature",
        )


def test_attestation_cannot_outlive_trusted_runner_key(repository):
    package = verify(repository)
    public_key, _ = generate_test_keypair()
    now = datetime.now(timezone.utc)
    repository.register_trusted_runner_key(
        key_id="runner-key-short-lived", runner_id="short-lived-runner",
        **runner_scope(package), public_key=public_key,
        valid_from=(now - timedelta(minutes=1)).isoformat(),
        valid_until=(now + timedelta(minutes=30)).isoformat(),
        registered_by="security-admin",
    )
    with pytest.raises(PermissionError, match="outside the trusted key validity"):
        repository.attest_external_adapter_evidence(
            package["id"], key_id="runner-key-short-lived",
            runner_id="short-lived-runner", nonce="nonce_" + "s" * 32,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
            signature="invalid-signature",
        )



def test_key_rotation_accepts_new_key_without_rewriting_old_key(repository):
    package = verify(repository)
    now = datetime.now(timezone.utc)
    old_public, _ = generate_test_keypair()
    new_public, new_private = generate_test_keypair()
    for key_id, public_key in (
        ("runner-key-old", old_public), ("runner-key-new", new_public)
    ):
        repository.register_trusted_runner_key(
            key_id=key_id, runner_id="rotating-runner",
            **runner_scope(package), public_key=public_key,
            valid_from=(now - timedelta(minutes=1)).isoformat(),
            valid_until=(now + timedelta(days=2)).isoformat(),
            registered_by="security-admin",
        )
    issued_at = now.isoformat()
    expires_at = (now + timedelta(hours=1)).isoformat()
    payload = build_attestation_payload(
        package_id=package["id"], manifest_sha256=package["manifest_sha256"],
        artifact_hashes=package["artifact_hashes"], runner_id="rotating-runner",
        provider_id=package["provider_id"], adapter_id=package["adapter_id"],
        adapter_version=package["adapter_version"],
        provider_scope=package["provider_scope"],
        sandbox_environment=package["sandbox_environment"],
        nonce="nonce_" + "r" * 32, issued_at=issued_at,
        expires_at=expires_at,
    )
    repository.attest_external_adapter_evidence(
        package["id"], key_id="runner-key-new", runner_id="rotating-runner",
        nonce=payload["nonce"], issued_at=issued_at, expires_at=expires_at,
        signature=sign_attestation_for_runner(new_private, payload),
    )
    assert repository.get_external_adapter_evidence_attestation(
        package["id"]
    )["key_id"] == "runner-key-new"



def test_certification_cannot_outlive_runner_attestation(repository):
    with pytest.raises(ValueError, match="runner attestation"):
        certify(
            repository,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=21)).isoformat(),
        )


def test_runner_key_and_attestation_records_are_immutable(repository):
    certificate = certify(repository)
    package_id = certificate["evidence_references"][0].split(":", 1)[1]
    attestation = repository.get_external_adapter_evidence_attestation(package_id)
    connection = repository.database.connect()
    with pytest.raises(Exception):
        connection.execute(
            "UPDATE trusted_runner_keys SET runner_id = 'attacker' WHERE key_id = ?",
            (attestation["key_id"],),
        )
    connection.rollback()
    with pytest.raises(Exception):
        connection.execute(
            "UPDATE external_adapter_evidence_attestations SET signature = 'forged' WHERE package_id = ?",
            (package_id,),
        )
    connection.rollback()



def test_revoked_public_key_cannot_be_re_registered_under_new_id(repository):
    public_key, _ = generate_test_keypair()
    now = datetime.now(timezone.utc)
    package = verify(repository)
    values = {
        "runner_id": "runner-key-alias",
        **runner_scope(package),
        "public_key": public_key,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=1)).isoformat(),
        "registered_by": "security-admin",
    }
    repository.register_trusted_runner_key(key_id="original-key", **values)
    repository.revoke_trusted_runner_key(
        "original-key", revoked_by="security-admin",
        reason="Compromised private key",
    )
    with pytest.raises(Exception):
        repository.register_trusted_runner_key(
            key_id="alias-key", **values
        )



def test_nonce_cannot_be_reused_across_distinct_evidence_packages(repository):
    first = verify(repository)
    second = verify(repository)
    public_key, private_key = generate_test_keypair()
    now = datetime.now(timezone.utc)
    key_id = "runner-key-global-nonce"
    repository.register_trusted_runner_key(
        key_id=key_id, runner_id="nonce-runner", **runner_scope(first), public_key=public_key,
        valid_from=(now - timedelta(minutes=1)).isoformat(),
        valid_until=(now + timedelta(days=2)).isoformat(),
        registered_by="security-admin",
    )
    nonce = "nonce_" + "g" * 32
    for package in (first, second):
        issued_at = datetime.now(timezone.utc).isoformat()
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        payload = build_attestation_payload(
            package_id=package["id"],
            manifest_sha256=package["manifest_sha256"],
            artifact_hashes=package["artifact_hashes"],
            runner_id="nonce-runner",
            provider_id=package["provider_id"],
            adapter_id=package["adapter_id"],
            adapter_version=package["adapter_version"],
            provider_scope=package["provider_scope"],
            sandbox_environment=package["sandbox_environment"],
            nonce=nonce, issued_at=issued_at, expires_at=expires_at,
        )
        signature = sign_attestation_for_runner(private_key, payload)
        if package is first:
            repository.attest_external_adapter_evidence(
                package["id"], key_id=key_id, runner_id="nonce-runner",
                nonce=nonce, issued_at=issued_at, expires_at=expires_at,
                signature=signature,
            )
        else:
            with pytest.raises(PermissionError, match="nonce has already been used"):
                repository.attest_external_adapter_evidence(
                    package["id"], key_id=key_id, runner_id="nonce-runner",
                    nonce=nonce, issued_at=issued_at, expires_at=expires_at,
                    signature=signature,
                )
