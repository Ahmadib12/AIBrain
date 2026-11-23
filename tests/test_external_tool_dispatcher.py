import json
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.tools import (
    ExternalToolExecutionOutcome,
    ExternalToolOutcomeStatus,
    FakeExternalToolProvider,
    ToolContract,
    ToolRisk,
    execution_action_digest,
)
from backend.app.tools.dispatcher import ExternalToolAdapterRegistry, ExternalToolDispatcher
from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository, _request_digest
from backend.app.tools.contracts import contract_fingerprint


def registry_for(provider):
    registry = ExternalToolAdapterRegistry()
    registry.register("send-message", provider)
    return registry


def contract():
    return ToolContract(
        tool_id="send-message",
        name="Send message",
        description="Send a message",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={
            "type": "object",
            "properties": {
                "recipient": {"type": "string"},
                "text": {"type": "string"},
            },
            "required": ["recipient", "text"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


class RepositoryStub:
    def __init__(self, *, outcome=None):
        self.outcome = outcome
        self.calls = []
        self.request_id = "request-1"
        self.user_id = "user-1"
        self.payload = {"recipient": "person@example.com", "text": "Hello"}
        self.binding = None
        self.status = "claimed"
        self.certification_available = True

    def get_active_external_adapter_certification(
        self, *, provider_id, adapter_id, adapter_version, provider_scope,
        tool_id, tool_contract_fingerprint, capabilities,
    ):
        if not self.certification_available:
            return None
        return {
            "id": "sandbox-certification-1",
            "provider_id": provider_id,
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "provider_scope": provider_scope,
            "tool_id": tool_id,
            "tool_contract_fingerprint": tool_contract_fingerprint,
            "capabilities": capabilities,
            "test_suite_version": "conformance-v1",
            "test_report_sha256": "a" * 64,
            "evidence_references": ["sandbox://evidence/report-1"],
            "approved_by": "test-operator",
        }

    def get(self, user_id, request_id):
        return {
            "tool_id": "send-message",
            "contract_fingerprint": contract_fingerprint(contract()),
        }

    def claim_passkey_authorized_for_execution(
        self, user_id, request_id, *, expected_contract_fingerprint
    ):
        self.calls.append("claim")
        assert user_id == self.user_id
        assert request_id == self.request_id
        return {"tool_id": "send-message", "arguments": self.payload}

    def create_execution_binding(self, user_id, request_id, **values):
        self.calls.append("binding")
        self.binding = {
            **values,
            "request_id": request_id,
            "payload_json": json.dumps(
                values["payload"], ensure_ascii=False,
                sort_keys=True, separators=(",", ":")
            ),
        }
        return self.binding

    def begin_external_dispatch(self, user_id, request_id, **values):
        self.calls.append("begin")
        return {
            "action_digest": self.binding["action_digest"],
            "idempotency_key": request_id,
        }

    def record_external_dispatch_outcome(self, user_id, request_id, **values):
        self.calls.append(("outcome", values["outcome"]))
        self.status = values["outcome"]

    def get_execution_attempt(self, user_id, request_id):
        return {"status": self.status}

    def get_execution_binding(self, user_id, request_id):
        return {
            **self.binding,
            "idempotency_key": self.request_id,
            "action_digest": self.binding["action_digest"],
            "capabilities": {
                "idempotency_mode": "provider_enforced",
                "key_scope": "provider-account-and-operation",
                "idempotency_retention_seconds": 86400,
                "rejects_payload_mismatch": True,
                "concurrent_deduplication": True,
                "supports_outcome_lookup": True,
            },
        }

    def record_external_outcome_lookup(self, user_id, request_id, **values):
        self.calls.append(("lookup", values["outcome"]))


def test_dispatch_uses_claim_binding_final_check_then_provider():
    repository = RepositoryStub()
    provider = FakeExternalToolProvider()
    dispatcher = ExternalToolDispatcher(repository, registry_for(provider))

    result = dispatcher.dispatch(
        "user-1", "request-1", contract=contract()
    )

    assert result["status"] == "completed"
    assert repository.calls[:3] == ["claim", "binding", "begin"]
    assert provider.dispatch_count == 1
    assert provider.effect_count == 1
    assert repository.calls[-1] == ("outcome", "succeeded")


def test_dispatch_fails_closed_without_matching_certification():
    repository = RepositoryStub()
    repository.certification_available = False
    provider = FakeExternalToolProvider()
    dispatcher = ExternalToolDispatcher(repository, registry_for(provider))

    with pytest.raises(PermissionError, match="sandbox certification"):
        dispatcher.dispatch("user-1", "request-1", contract=contract())

    assert repository.calls == []
    assert provider.dispatch_count == 0
    assert provider.effect_count == 0


def test_transport_timeout_becomes_unknown_without_retry():
    repository = RepositoryStub()
    provider = FakeExternalToolProvider()
    provider.timeout_after_accept_once = True
    dispatcher = ExternalToolDispatcher(repository, registry_for(provider))

    result = dispatcher.dispatch(
        "user-1", "request-1", contract=contract()
    )

    assert result == {
        "status": "outcome_unknown",
        "request_id": "request-1",
        "automatic_retry": False,
    }
    assert provider.dispatch_count == 1
    assert provider.effect_count == 1
    assert repository.calls[-1] == ("outcome", "unknown")


def test_definitive_provider_failure_is_recorded_as_failed():
    repository = RepositoryStub(
        outcome=ExternalToolExecutionOutcome(
            status=ExternalToolOutcomeStatus.FAILED,
            error_code="provider_rejected",
        )
    )
    class FailedProvider(FakeExternalToolProvider):
        def execute(self, action):
            self.dispatch_count += 1
            return repository.outcome

    provider = FailedProvider()
    result = ExternalToolDispatcher(repository, registry_for(provider)).dispatch(
        "user-1", "request-1", contract=contract()
    )

    assert result["status"] == "failed"
    assert repository.calls[-1] == ("outcome", "failed")


def test_read_only_contract_cannot_use_external_dispatch():
    repository = RepositoryStub()
    read_only = ToolContract(
        tool_id="send-message",
        name="Send message",
        description="Send a message",
        risk=ToolRisk.READ_ONLY,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
    )
    provider = FakeExternalToolProvider()
    with pytest.raises(PermissionError, match="state-change"):
        ExternalToolDispatcher(repository, registry_for(provider)).dispatch(
            "user-1", "request-1",
            contract=read_only,
        )
    assert repository.calls == []


def test_lookup_is_read_only_and_requires_unknown_outcome():
    repository = RepositoryStub()
    provider = FakeExternalToolProvider()
    dispatcher = ExternalToolDispatcher(repository, registry_for(provider))
    dispatcher.dispatch(
        "user-1", "request-1", contract=contract()
    )
    repository.status = "outcome_unknown"
    outcome = dispatcher.lookup("user-1", "request-1")

    assert outcome.status is ExternalToolOutcomeStatus.SUCCEEDED
    assert provider.dispatch_count == 1
    assert provider.lookup_count == 1
    assert repository.calls[-1] == ("lookup", "succeeded")


def claimed_passkey_dispatch(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'passkey-dispatch.db'}")
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    user_id = "passkey-dispatch-owner"
    request_id = None
    database.connect().execute(
        """
        INSERT INTO users (id, email, password_salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, "dispatch-owner@example.com", "salt", "hash", now_text),
    )
    database.connect().commit()
    repository = ToolRequestRepository(database)
    tool_contract = contract()
    fingerprint = contract_fingerprint(tool_contract)
    arguments = {"recipient": "person@example.com", "text": "Hello"}
    request = repository.create(
        user_id,
        tool_id=tool_contract.tool_id,
        arguments=arguments,
        status="approved",
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        contract_fingerprint=fingerprint,
        authorization_policy="passkey",
    )
    request_id = request["id"]
    proposal_digest = _request_digest(
        tool_contract.tool_id, arguments, fingerprint
    )
    credential_id = str(uuid.uuid4())
    challenge_id = str(uuid.uuid4())
    authorization_id = str(uuid.uuid4())
    database.connect().execute(
        """
        INSERT INTO webauthn_credentials
            (id, user_id, credential_id, public_key, sign_count, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
        """,
        (credential_id, user_id, "credential-dispatch", b"public-key", now_text),
    )
    database.connect().execute(
        """
        INSERT INTO webauthn_challenges
            (id, user_id, challenge_hash, purpose, request_id,
             proposal_digest, contract_fingerprint, expires_at,
             consumed_at, created_at)
        VALUES (?, ?, ?, 'tool_approval', ?, ?, ?, ?, ?, ?)
        """,
        (
            challenge_id, user_id, hashlib.sha256(b"challenge").hexdigest(),
            request_id, proposal_digest, fingerprint,
            (now + timedelta(minutes=5)).isoformat(), now_text, now_text,
        ),
    )
    database.connect().execute(
        """
        INSERT INTO tool_authorizations
            (id, user_id, request_id, challenge_id, credential_id,
             proposal_digest, contract_fingerprint, authorized_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            authorization_id, user_id, request_id, challenge_id,
            credential_id, proposal_digest, fingerprint, now_text,
        ),
    )
    database.connect().commit()
    repository.claim_passkey_authorized_for_execution(
        user_id, request_id, expected_contract_fingerprint=fingerprint
    )
    provider = FakeExternalToolProvider()
    caps = provider.capabilities
    snapshot = {
        "idempotency_mode": caps.idempotency_mode.value,
        "key_scope": caps.key_scope,
        "idempotency_retention_seconds": caps.idempotency_retention_seconds,
        "rejects_payload_mismatch": caps.rejects_payload_mismatch,
        "concurrent_deduplication": caps.concurrent_deduplication,
        "supports_outcome_lookup": caps.supports_outcome_lookup,
    }
    digest = execution_action_digest(
        user_id=user_id,
        tool_id=tool_contract.tool_id,
        arguments=arguments,
        contract_fingerprint=fingerprint,
        adapter_id=caps.adapter_id,
        adapter_version=caps.adapter_version,
        provider_id=caps.provider_id,
        provider_scope=caps.provider_scope,
    )
    repository.create_execution_binding(
        user_id,
        request_id,
        idempotency_key=request_id,
        action_digest=digest,
        payload=arguments,
        tool_contract_fingerprint=fingerprint,
        adapter_id=caps.adapter_id,
        adapter_version=caps.adapter_version,
        provider_id=caps.provider_id,
        provider_scope=caps.provider_scope,
        capabilities=snapshot,
    )

    # A final dispatch must revalidate an actual signed evidence package,
    # not rely only on a mocked "certification available" response.
    from backend.app.tools.attestation import (
        build_attestation_payload, generate_test_keypair, sign_attestation_for_runner,
    )
    from backend.app.tools.conformance import REQUIRED_CHECKS
    artifact_bytes = b"fake provider conformance runner evidence"
    artifacts = {"runner-report.bin": artifact_bytes}
    executed_at = now - timedelta(minutes=1)
    evidence_expires = now + timedelta(days=5)
    manifest = {
        "schema_version": "aibrain-conformance-evidence-v1",
        "provider_id": caps.provider_id,
        "adapter_id": caps.adapter_id,
        "adapter_version": caps.adapter_version,
        "provider_scope": caps.provider_scope,
        "tool_id": tool_contract.tool_id,
        "tool_contract_fingerprint": fingerprint,
        "capabilities": snapshot,
        "test_suite_version": "conformance-v1",
        "sandbox_environment": "fake-provider-test-sandbox",
        "executed_at": executed_at.isoformat(),
        "expires_at": evidence_expires.isoformat(),
        "tests": {
            name: {"status": "passed", "artifact": "runner-report.bin"}
            for name in REQUIRED_CHECKS
        },
        "artifacts": {
            "runner-report.bin": hashlib.sha256(artifact_bytes).hexdigest()
        },
    }
    package = repository.verify_external_adapter_evidence(manifest, artifacts)
    public_key, private_key = generate_test_keypair()
    key_id = "dispatcher-runner-key"
    repository.register_trusted_runner_key(
        key_id=key_id, runner_id="dispatcher-test-runner",
        public_key=public_key,
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=10)).isoformat(),
        registered_by="test-security-admin",
    )
    issued_at = now.isoformat()
    attestation_expires = (now + timedelta(hours=20)).isoformat()
    nonce = "nonce_" + uuid.uuid4().hex
    payload = build_attestation_payload(
        package_id=package["id"],
        manifest_sha256=package["manifest_sha256"],
        artifact_hashes=package["artifact_hashes"],
        runner_id="dispatcher-test-runner",
        provider_id=caps.provider_id,
        adapter_id=caps.adapter_id,
        adapter_version=caps.adapter_version,
        provider_scope=caps.provider_scope,
        sandbox_environment="fake-provider-test-sandbox",
        nonce=nonce, issued_at=issued_at, expires_at=attestation_expires,
    )
    repository.attest_external_adapter_evidence(
        package["id"], key_id=key_id, runner_id="dispatcher-test-runner",
        nonce=nonce, issued_at=issued_at, expires_at=attestation_expires,
        signature=sign_attestation_for_runner(private_key, payload),
    )
    repository.certify_external_adapter(
        evidence_package_id=package["id"], approved_by="test-operator",
        expires_at=(now + timedelta(hours=12)).isoformat(),
    )
    return database, repository, user_id, request_id, fingerprint, provider, snapshot


def test_final_dispatch_gate_rechecks_passkey_and_audits_start(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    try:
        frozen = repository.begin_external_dispatch(
            user_id,
            request_id,
            expected_contract_fingerprint=fingerprint,
            adapter_id=provider.capabilities.adapter_id,
            adapter_version=provider.capabilities.adapter_version,
            provider_id=provider.capabilities.provider_id,
            provider_scope=provider.capabilities.provider_scope,
            capabilities=snapshot,
        )
        assert len(frozen["action_digest"]) == 64
        audit = repository.get_dispatch_audit(user_id, request_id)
        assert [event["event_type"] for event in audit] == ["dispatch_started"]
        with pytest.raises(PermissionError, match="already been initiated"):
            repository.begin_external_dispatch(
                user_id,
                request_id,
                expected_contract_fingerprint=fingerprint,
                adapter_id=provider.capabilities.adapter_id,
                adapter_version=provider.capabilities.adapter_version,
                provider_id=provider.capabilities.provider_id,
                provider_scope=provider.capabilities.provider_scope,
                capabilities=snapshot,
            )
    finally:
        database.close()



def test_unknown_provider_outcome_is_audited_and_not_retried(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    try:
        frozen = repository.begin_external_dispatch(
            user_id,
            request_id,
            expected_contract_fingerprint=fingerprint,
            adapter_id=provider.capabilities.adapter_id,
            adapter_version=provider.capabilities.adapter_version,
            provider_id=provider.capabilities.provider_id,
            provider_scope=provider.capabilities.provider_scope,
            capabilities=snapshot,
        )
        repository.record_external_dispatch_outcome(
            user_id,
            request_id,
            outcome="unknown",
            action_digest=frozen["action_digest"],
            error_code="provider_outcome_unknown",
        )
        assert repository.get(user_id, request_id)["status"] == "outcome_unknown"
        assert repository.get_execution_attempt(user_id, request_id)["status"] == "outcome_unknown"
        with pytest.raises(PermissionError, match="already been recorded"):
            repository.record_external_dispatch_outcome(
                user_id,
                request_id,
                outcome="succeeded",
                action_digest=frozen["action_digest"],
                result={"accepted": True},
            )
        repository.record_external_outcome_lookup(
            user_id,
            request_id,
            action_digest=frozen["action_digest"],
            outcome="unknown",
            evidence_reference="provider-lookup-1",
        )
        audit = repository.get_dispatch_audit(user_id, request_id)
        assert [event["event_type"] for event in audit] == [
            "dispatch_started", "dispatch_unknown", "outcome_lookup"
        ]
        assert repository.get(user_id, request_id)["status"] == "outcome_unknown"
    finally:
        database.close()


def test_final_dispatch_gate_rejects_revoked_passkey(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    try:
        database.connect().execute(
            "UPDATE webauthn_credentials SET revoked_at = ? WHERE user_id = ?",
            (datetime.now(timezone.utc).isoformat(), user_id),
        )
        database.connect().commit()
        with pytest.raises(PermissionError, match="passkey authorization"):
            repository.begin_external_dispatch(
                user_id,
                request_id,
                expected_contract_fingerprint=fingerprint,
                adapter_id=provider.capabilities.adapter_id,
                adapter_version=provider.capabilities.adapter_version,
                provider_id=provider.capabilities.provider_id,
                provider_scope=provider.capabilities.provider_scope,
                capabilities=snapshot,
            )
        assert repository.get_dispatch_audit(user_id, request_id) == []
    finally:
        database.close()
