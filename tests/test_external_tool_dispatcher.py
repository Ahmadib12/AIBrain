import json
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
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
        provider_id=package["provider_id"],
        adapter_id=package["adapter_id"],
        adapter_version=package["adapter_version"],
        provider_scope=package["provider_scope"],
        tool_id=package["tool_id"],
        tool_contract_fingerprint=package["tool_contract_fingerprint"],
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


def test_recovery_marks_bound_dispatch_failed_before_provider_boundary(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    try:
        stale_before = (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat()
        assert repository.recover_stale_execution_attempts(
            stale_before=stale_before
        ) == 1

        request = repository.get(user_id, request_id)
        attempt = repository.get_execution_attempt(user_id, request_id)
        assert request["status"] == "failed"
        assert attempt["status"] == "failed"
        assert attempt["error_code"] == "recovery_dispatch_not_started"
        assert attempt["finished_at"] is not None

        recovery_events = database.connect().execute(
            """
            SELECT event_type, action_digest, details_json
            FROM tool_dispatch_recovery_events
            WHERE user_id = ? AND request_id = ?
            """,
            (user_id, request_id),
        ).fetchall()
        assert len(recovery_events) == 1
        assert recovery_events[0]["event_type"] == "dispatch_not_started"
        assert len(recovery_events[0]["action_digest"]) == 64
        details = json.loads(recovery_events[0]["details_json"])
        assert details["reason"] == "stale_claim_before_provider_dispatch"

        dispatcher = ExternalToolDispatcher(repository, registry_for(provider))
        with pytest.raises(PermissionError, match="unknown outcomes"):
            dispatcher.lookup(user_id, request_id)
        assert provider.dispatch_count == 0
        assert provider.lookup_count == 0
    finally:
        database.close()


def test_recovery_keeps_started_external_dispatch_unknown_and_lookupable(tmp_path):
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
        stale_before = (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat()
        assert repository.recover_stale_execution_attempts(
            stale_before=stale_before
        ) == 1

        assert repository.get(user_id, request_id)["status"] == "outcome_unknown"
        attempt = repository.get_execution_attempt(user_id, request_id)
        assert attempt["status"] == "outcome_unknown"
        assert attempt["error_code"] == "recovery_outcome_unknown"
        assert repository.get_dispatch_audit(user_id, request_id)[0][
            "event_type"
        ] == "dispatch_started"
        assert database.connect().execute(
            "SELECT COUNT(*) FROM tool_dispatch_recovery_events "
            "WHERE request_id = ?",
            (request_id,),
        ).fetchone()[0] == 0

        dispatcher = ExternalToolDispatcher(repository, registry_for(provider))
        outcome = dispatcher.lookup(user_id, request_id)
        assert isinstance(outcome, ExternalToolExecutionOutcome)
        assert provider.dispatch_count == 0
        assert provider.lookup_count == 1
        assert [event["event_type"] for event in repository.get_dispatch_audit(
            user_id, request_id
        )] == ["dispatch_started", "outcome_lookup"]
    finally:
        database.close()


def test_recovery_racing_dispatch_start_is_serialized(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    second_database = Database(database.database_url)
    second_repository = ToolRequestRepository(second_database)
    barrier = Barrier(2)
    stale_before = (
        datetime.now(timezone.utc) + timedelta(minutes=1)
    ).isoformat()

    def start_dispatch():
        barrier.wait(timeout=10)
        try:
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
            return "started"
        except PermissionError:
            return "rejected"

    def recover():
        barrier.wait(timeout=10)
        return second_repository.recover_stale_execution_attempts(
            stale_before=stale_before
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            start_future = executor.submit(start_dispatch)
            recovery_future = executor.submit(recover)
            start_result = start_future.result(timeout=20)
            recovered = recovery_future.result(timeout=20)

        assert recovered == 1
        request = repository.get(user_id, request_id)
        attempt = repository.get_execution_attempt(user_id, request_id)
        if start_result == "started":
            assert request["status"] == "outcome_unknown"
            assert attempt["status"] == "outcome_unknown"
            assert repository.get_dispatch_audit(user_id, request_id)[0][
                "event_type"
            ] == "dispatch_started"
            assert database.connect().execute(
                "SELECT COUNT(*) FROM tool_dispatch_recovery_events "
                "WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0] == 0
        else:
            assert request["status"] == "failed"
            assert attempt["status"] == "failed"
            assert repository.get_dispatch_audit(user_id, request_id) == []
            assert database.connect().execute(
                "SELECT COUNT(*) FROM tool_dispatch_recovery_events "
                "WHERE request_id = ?",
                (request_id,),
            ).fetchone()[0] == 1
        # This test only calls the durable start gate; it never invokes execute.
        assert provider.dispatch_count == 0
    finally:
        second_database.close()
        database.close()


def test_lookup_rejects_revoked_adapter_certification(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    try:
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
        repository.record_external_dispatch_outcome(
            user_id,
            request_id,
            outcome="unknown",
            action_digest=repository.get_execution_binding(
                user_id, request_id
            )["action_digest"],
            error_code="provider_outcome_unknown",
        )
        certification = repository.get_active_external_adapter_certification(
            provider_id=provider.capabilities.provider_id,
            adapter_id=provider.capabilities.adapter_id,
            adapter_version=provider.capabilities.adapter_version,
            provider_scope=provider.capabilities.provider_scope,
            tool_id=contract().tool_id,
            tool_contract_fingerprint=fingerprint,
            capabilities=snapshot,
        )
        assert certification is not None
        repository.revoke_external_adapter_certification(
            certification["id"],
            revoked_by="test-security-admin",
            reason="Test revocation before provider outcome lookup",
        )

        dispatcher = ExternalToolDispatcher(repository, registry_for(provider))
        with pytest.raises(PermissionError, match="active, matching trusted certification"):
            dispatcher.lookup(user_id, request_id)

        assert provider.dispatch_count == 0
        assert provider.lookup_count == 0
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



def test_final_dispatch_gate_rejects_revoked_runner_key(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    try:
        certificate_row = database.connect().execute(
            "SELECT evidence_references_json FROM external_adapter_certifications"
        ).fetchone()
        package_id = json.loads(certificate_row["evidence_references_json"])[0].split(":", 1)[1]
        attestation = repository.get_external_adapter_evidence_attestation(package_id)
        repository.revoke_trusted_runner_key(
            attestation["key_id"], revoked_by="security-admin",
            reason="Test runner key compromise",
        )
        with pytest.raises(PermissionError, match="trusted evidence certification"):
            repository.begin_external_dispatch(
                user_id, request_id,
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



def _begin_dispatch(repository, user_id, request_id, fingerprint, provider, snapshot):
    return repository.begin_external_dispatch(
        user_id,
        request_id,
        expected_contract_fingerprint=fingerprint,
        adapter_id=provider.capabilities.adapter_id,
        adapter_version=provider.capabilities.adapter_version,
        provider_id=provider.capabilities.provider_id,
        provider_scope=provider.capabilities.provider_scope,
        capabilities=snapshot,
    )


def test_concurrent_dispatch_start_is_single_use_across_database_connections(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    second_database = Database(database.database_url)
    second_repository = ToolRequestRepository(second_database)
    barrier = Barrier(2)

    def attempt(candidate):
        barrier.wait(timeout=10)
        try:
            _begin_dispatch(
                candidate, user_id, request_id, fingerprint, provider, snapshot
            )
        except PermissionError:
            return "rejected"
        return "accepted"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(attempt, (repository, second_repository)))
        assert sorted(outcomes) == ["accepted", "rejected"]
        audit = repository.get_dispatch_audit(user_id, request_id)
        assert [event["event_type"] for event in audit] == ["dispatch_started"]
    finally:
        second_database.close()
        database.close()


def test_runner_key_revocation_racing_dispatch_is_linearized(tmp_path):
    (
        database, repository, user_id, request_id, fingerprint, provider, snapshot
    ) = claimed_passkey_dispatch(tmp_path)
    second_database = Database(database.database_url)
    second_repository = ToolRequestRepository(second_database)
    barrier = Barrier(2)

    def dispatch_attempt():
        barrier.wait(timeout=10)
        try:
            _begin_dispatch(
                repository, user_id, request_id, fingerprint, provider, snapshot
            )
        except PermissionError:
            return "rejected"
        return "accepted"

    def revoke_attempt():
        barrier.wait(timeout=10)
        second_repository.revoke_trusted_runner_key(
            "dispatcher-runner-key",
            revoked_by="concurrent-security-operator",
            reason="Concurrency test revocation",
        )
        return "revoked"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            dispatch_future = executor.submit(dispatch_attempt)
            revoke_future = executor.submit(revoke_attempt)
            dispatch_result = dispatch_future.result(timeout=15)
            assert revoke_future.result(timeout=15) == "revoked"

        revocation_count = repository.database.connect().execute(
            "SELECT COUNT(*) FROM trusted_runner_key_revocations "
            "WHERE key_id = ?",
            ("dispatcher-runner-key",),
        ).fetchone()[0]
        assert revocation_count == 1

        audit = repository.get_dispatch_audit(user_id, request_id)
        starts = [event for event in audit if event["event_type"] == "dispatch_started"]
        if dispatch_result == "accepted":
            # Dispatch acquired the SQLite write transaction first; revocation
            # committed only after the final authorization gate completed.
            assert len(starts) == 1
        else:
            # Revocation committed first; the final dispatch gate must fail closed.
            assert starts == []
    finally:
        second_database.close()
        database.close()
