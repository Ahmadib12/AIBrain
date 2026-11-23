import json
import sqlite3

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.tools.contracts import execution_action_digest


def setup_claimed_request(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'dispatch-binding.db'}")
    now = "2026-11-23T00:00:00+00:00"
    user_id = "binding-owner"
    database.connect().execute(
        """
        INSERT INTO users (id, email, password_salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, "binding-owner@example.com", "salt", "hash", now),
    )
    database.connect().commit()
    repository = ToolRequestRepository(database)
    arguments = {"recipient": "person@example.com", "text": "Approved message"}
    fingerprint = "b" * 64
    request = repository.create(
        user_id,
        tool_id="send-message",
        arguments=arguments,
        status="approved",
        contract_fingerprint=fingerprint,
        authorization_policy="read_only",
    )
    repository.claim_for_execution(
        user_id,
        request["id"],
        expected_contract_fingerprint=fingerprint,
    )
    return database, repository, user_id, request, arguments, fingerprint


def make_binding(repository, user_id, request, arguments, fingerprint, **overrides):
    values = {
        "idempotency_key": request["id"],
        "action_digest": execution_action_digest(
            user_id=user_id,
            tool_id="send-message",
            arguments=arguments,
            contract_fingerprint=fingerprint,
            adapter_id="fake-adapter",
            adapter_version="1",
            provider_id="fake-provider",
            provider_scope="fake-account",
        ),
        "payload": arguments,
        "tool_contract_fingerprint": fingerprint,
        "adapter_id": "fake-adapter",
        "adapter_version": "1",
        "provider_id": "fake-provider",
        "provider_scope": "fake-account",
        "capabilities": {
            "idempotency_mode": "provider_enforced",
            "key_scope": "provider-account-and-operation",
            "idempotency_retention_seconds": 86400,
            "rejects_payload_mismatch": True,
            "concurrent_deduplication": True,
            "supports_outcome_lookup": True,
        },
    }
    values.update(overrides)
    return repository.create_execution_binding(
        user_id,
        request["id"],
        **values,
    )


def test_persists_owner_scoped_immutable_dispatch_binding(tmp_path):
    database, repository, user_id, request, arguments, fingerprint = (
        setup_claimed_request(tmp_path)
    )
    try:
        binding = make_binding(
            repository, user_id, request, arguments, fingerprint
        )

        assert binding["request_id"] == request["id"]
        assert binding["idempotency_key"] == request["id"]
        assert binding["action_digest"] == execution_action_digest(
            user_id=user_id,
            tool_id="send-message",
            arguments=arguments,
            contract_fingerprint=fingerprint,
            adapter_id="fake-adapter",
            adapter_version="1",
            provider_scope="fake-account",
        )
        assert binding["payload"] == arguments
        assert binding["capabilities"]["idempotency_mode"] == "provider_enforced"

        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            database.connect().execute(
                "UPDATE tool_execution_bindings SET provider_scope = ? WHERE request_id = ?",
                ("other-account", request["id"]),
            )
        database.connect().rollback()

        with pytest.raises(sqlite3.IntegrityError):
            database.connect().execute(
                "INSERT INTO tool_execution_bindings SELECT "
                "?, user_id, request_id, ?, action_digest, payload_json, "
                "tool_contract_fingerprint, adapter_id, adapter_version, "
                "provider_id, provider_scope, capabilities_json, created_at "
                "FROM tool_execution_bindings WHERE request_id = ?",
                ("duplicate-binding", "another-key", request["id"]),
            )
        database.connect().rollback()
    finally:
        database.close()


@pytest.mark.parametrize(
    "overrides",
    [
        {"payload": {"recipient": "attacker@example.com", "text": "Changed"}},
        {"idempotency_key": "different-request"},
        {"tool_contract_fingerprint": "c" * 64},
        {"adapter_id": "different-adapter"},
        {"provider_id": "different-provider"},
        {"action_digest": "d" * 64},
    ],
)
def test_rejects_dispatch_binding_that_does_not_match_authorized_action(
    tmp_path, overrides
):
    database, repository, user_id, request, arguments, fingerprint = (
        setup_claimed_request(tmp_path)
    )
    try:
        with pytest.raises(PermissionError):
            make_binding(
                repository,
                user_id,
                request,
                arguments,
                fingerprint,
                **overrides,
            )
        assert database.connect().execute(
            "SELECT COUNT(*) FROM tool_execution_bindings"
        ).fetchone()[0] == 0
    finally:
        database.close()


def test_non_idempotent_capability_snapshot_can_be_persisted(tmp_path):
    database, repository, user_id, request, arguments, fingerprint = (
        setup_claimed_request(tmp_path)
    )
    try:
        binding = make_binding(
            repository,
            user_id,
            request,
            arguments,
            fingerprint,
            capabilities={
                "idempotency_mode": "none",
                "key_scope": None,
                "idempotency_retention_seconds": None,
                "rejects_payload_mismatch": False,
                "concurrent_deduplication": False,
                "supports_outcome_lookup": True,
            },
        )
        assert binding["capabilities"]["idempotency_mode"] == "none"
        assert binding["capabilities"]["key_scope"] is None
    finally:
        database.close()


def test_binding_requires_a_claimed_execution_and_owner_scope(tmp_path):
    database, repository, user_id, request, arguments, fingerprint = (
        setup_claimed_request(tmp_path)
    )
    try:
        with pytest.raises(LookupError):
            repository.get_execution_binding("another-user", request["id"])

        other_request = repository.create(
            user_id,
            tool_id="send-message",
            arguments=arguments,
            status="approved",
            contract_fingerprint=fingerprint,
            authorization_policy="read_only",
        )
        with pytest.raises(PermissionError):
            repository.create_execution_binding(
                user_id,
                other_request["id"],
                idempotency_key=other_request["id"],
                action_digest="e" * 64,
                payload=arguments,
                tool_contract_fingerprint=fingerprint,
                adapter_id="fake-adapter",
                adapter_version="1",
                provider_id="fake-provider",
                provider_scope="fake-account",
                capabilities={
                    "idempotency_mode": "provider_enforced",
                    "key_scope": "provider-account-and-operation",
                    "idempotency_retention_seconds": 86400,
                    "rejects_payload_mismatch": True,
                    "concurrent_deduplication": True,
                    "supports_outcome_lookup": True,
                },
            )
    finally:
        database.close()


def test_only_one_binding_can_be_created_for_a_request(tmp_path):
    database, repository, user_id, request, arguments, fingerprint = (
        setup_claimed_request(tmp_path)
    )
    try:
        make_binding(repository, user_id, request, arguments, fingerprint)
        with pytest.raises(sqlite3.IntegrityError):
            make_binding(repository, user_id, request, arguments, fingerprint)
        assert database.connect().execute(
            "SELECT COUNT(*) FROM tool_execution_bindings WHERE request_id = ?",
            (request["id"],),
        ).fetchone()[0] == 1
    finally:
        database.close()


def test_binding_payload_and_capabilities_are_stored_as_canonical_json(tmp_path):
    database, repository, user_id, request, arguments, fingerprint = (
        setup_claimed_request(tmp_path)
    )
    try:
        binding = make_binding(
            repository, user_id, request, arguments, fingerprint
        )
        row = database.connect().execute(
            "SELECT payload_json, capabilities_json "
            "FROM tool_execution_bindings WHERE request_id = ?",
            (request["id"],),
        ).fetchone()
        assert row["payload_json"] == json.dumps(
            arguments, sort_keys=True, separators=(",", ":")
        )
        assert json.loads(row["capabilities_json"]) == binding["capabilities"]
    finally:
        database.close()


def test_binding_rejects_incomplete_capability_snapshot(tmp_path):
    database, repository, user_id, request, arguments, fingerprint = (
        setup_claimed_request(tmp_path)
    )
    try:
        with pytest.raises(ValueError, match="complete supported snapshot"):
            make_binding(
                repository,
                user_id,
                request,
                arguments,
                fingerprint,
                capabilities={
                    "idempotency_mode": "none",
                    "supports_outcome_lookup": True,
                },
            )
        assert database.connect().execute(
            "SELECT COUNT(*) FROM tool_execution_bindings"
        ).fetchone()[0] == 0
    finally:
        database.close()
