import os
import uuid

import pytest

from backend.app.persistence.postgres.migrations import PostgresMigrationRunner


def test_real_postgres_identity_and_authorization_migrations_are_idempotent():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 3
    assert runner.migrate() == 2

    user_id = str(uuid.uuid4())
    deleted_user_id = str(uuid.uuid4())
    email = f"postgres-migration-{user_id}@example.invalid"
    deleted_email = f"postgres-deleted-{deleted_user_id}@example.invalid"
    request_id = "request-" + user_id
    credential_id = "credential-" + user_id
    challenge_id = "challenge-" + user_id
    recovery_id = "recovery-" + user_id
    authorization_id = "authorization-" + user_id
    timestamp = "2026-01-01T00:00:00+00:00"

    with psycopg.connect(database_url) as connection:
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO users (
                    id, email, password_salt, password_hash, created_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, email, "salt", "hash", timestamp),
            )
            connection.execute(
                """
                INSERT INTO users (
                    id, email, password_salt, password_hash, created_at, deleted_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (deleted_user_id, deleted_email, "salt", "hash", timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO sessions (
                    token_hash, user_id, expires_at, created_at
                ) VALUES (%s, %s, %s, %s)
                """,
                ("token-" + user_id, user_id, "2027-01-01T00:00:00+00:00", timestamp),
            )
            connection.execute(
                """
                INSERT INTO memory_items (
                    id, user_id, memory_type, key, value_json, source,
                    confidence, status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                ("memory-" + user_id, user_id, "preference", "theme", '"dark"',
                 "user", 1.0, "active", timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO observations (
                    id, user_id, source, observation_json, status, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                ("observation-" + user_id, user_id, "test", '{"ok":true}',
                 "pending", timestamp),
            )
            connection.execute(
                """
                INSERT INTO adaptations (
                    id, user_id, proposal_json, status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                ("adaptation-" + user_id, user_id, '{"change":"test"}',
                 "proposed", timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_requests (
                    id, user_id, tool_id, arguments_json, status,
                    created_at, updated_at, authorization_policy
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (request_id, user_id, "echo", '{"text":"safe"}', "pending",
                 timestamp, timestamp, "passkey"),
            )
            connection.execute(
                """
                INSERT INTO webauthn_credentials (
                    id, user_id, credential_id, public_key, created_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (credential_id, user_id, "external-" + credential_id,
                 bytes(range(32)), timestamp),
            )
            connection.execute(
                """
                INSERT INTO webauthn_challenges (
                    id, user_id, challenge_hash, purpose, request_id,
                    expires_at, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (challenge_id, user_id, "hash-" + challenge_id, "tool_approval",
                 request_id, "2027-01-01T00:00:00+00:00", timestamp),
            )
            connection.execute(
                """
                INSERT INTO webauthn_recovery_codes (
                    id, user_id, code_hash, created_at
                ) VALUES (%s, %s, %s, %s)
                """,
                (recovery_id, user_id, "hash-" + recovery_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_authorizations (
                    id, user_id, request_id, challenge_id, credential_id,
                    proposal_digest, contract_fingerprint, authorized_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (authorization_id, user_id, request_id, challenge_id,
                 credential_id, "a" * 64, "b" * 64, timestamp),
            )
            connection.execute(
                """
                UPDATE tool_requests
                SET status='executing', consumed_at=%s, updated_at=%s
                WHERE id=%s
                """,
                (timestamp, timestamp, request_id),
            )
            execution_id = "execution-" + user_id
            binding_id = "binding-" + user_id
            digest = "c" * 64
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key, status,
                    claimed_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (execution_id, user_id, request_id, request_id, "claimed",
                 timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_execution_bindings (
                    id, user_id, request_id, idempotency_key, action_digest,
                    payload_json, tool_contract_fingerprint, adapter_id,
                    adapter_version, provider_id, provider_scope,
                    capabilities_json, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (binding_id, user_id, request_id, request_id, digest, "{}",
                 "d" * 64, "test-adapter", "1", "test-provider", "test",
                 "[]", timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_dispatch_audit_events (
                    id, user_id, request_id, event_type, action_digest,
                    details_json, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("dispatch-start-" + user_id, user_id, request_id,
                 "dispatch_started", digest, "{}", timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_dispatch_audit_events (
                    id, user_id, request_id, event_type, action_digest,
                    details_json, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("dispatch-success-" + user_id, user_id, request_id,
                 "dispatch_succeeded", digest, "{}", timestamp),
            )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO webauthn_credentials (
                        id, user_id, credential_id, public_key, backed_up, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    ("bad-backup-" + user_id, user_id, "bad-backup-external-" + user_id,
                     bytes(range(32)), 2, timestamp),
                )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO tool_requests (
                        id, user_id, tool_id, arguments_json, status,
                        created_at, updated_at, authorization_policy
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("bad-policy-" + user_id, user_id, "echo", "{}", "pending",
                     timestamp, timestamp, "bypass"),
                )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO memory_items (
                        id, user_id, memory_type, key, value_json, source,
                        confidence, status, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("blocked-" + deleted_user_id, deleted_user_id, "preference",
                     "theme", '"dark"', "user", 1.0, "active", timestamp, timestamp),
                )

        with connection.transaction():
            connection.execute("DELETE FROM tool_dispatch_audit_events WHERE request_id=%s", (request_id,))
            connection.execute("DELETE FROM tool_execution_bindings WHERE id=%s", ("binding-" + user_id,))
            connection.execute("DELETE FROM tool_execution_attempts WHERE id=%s", ("execution-" + user_id,))
            connection.execute("DELETE FROM tool_authorizations WHERE id=%s", (authorization_id,))
            connection.execute("DELETE FROM webauthn_challenges WHERE id=%s", (challenge_id,))
            connection.execute("DELETE FROM webauthn_recovery_codes WHERE id=%s", (recovery_id,))
            connection.execute("DELETE FROM webauthn_credentials WHERE id=%s", (credential_id,))
            connection.execute("DELETE FROM tool_requests WHERE id=%s", (request_id,))
            connection.execute("DELETE FROM adaptations WHERE id=%s", ("adaptation-" + user_id,))
            connection.execute("DELETE FROM observations WHERE id=%s", ("observation-" + user_id,))
            connection.execute("DELETE FROM memory_items WHERE id=%s", ("memory-" + user_id,))
            connection.execute("DELETE FROM sessions WHERE token_hash=%s", ("token-" + user_id,))
            connection.execute("DELETE FROM users WHERE id=%s", (user_id,))
            connection.execute("DELETE FROM users WHERE id=%s", (deleted_user_id,))

        applied = connection.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        ).fetchall()
        assert applied == [
            (1, "core_identity"),
            (2, "memory_tool_requests_and_passkey_authorization"),
            (3, "tool_execution_attempts_bindings_and_dispatch_audit"),
        ]
