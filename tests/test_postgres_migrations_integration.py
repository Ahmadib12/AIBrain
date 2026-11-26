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
    assert runner.migrate() == 11
    assert runner.migrate() == 11

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
            connection.execute(
                "UPDATE users SET deleted_at=%s WHERE id=%s",
                (timestamp, user_id),
            )
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
            (4, "external_adapter_certifications_and_revocations"),
            (5, "external_adapter_evidence_packages_and_artifacts"),
            (6, "trusted_runner_keys_and_evidence_attestations"),
            (7, "security_operator_audit_events"),
            (8, "tool_dispatch_recovery_events"),
            (9, "tool_dispatch_lookup_authorizations"),
            (10, "dispatch_audit_recovery_and_lookup_erasure_guards"),
            (11, "tool_execution_reconciliation_events"),
        ]



def test_real_postgres_external_evidence_and_operator_audit_are_immutable():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 11

    suffix = str(uuid.uuid4())
    runner_public_key = uuid.uuid4().bytes + uuid.uuid4().bytes
    timestamp = "2026-01-01T00:00:00+00:00"
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            INSERT INTO users (
                id, email, password_salt, password_hash, created_at
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            ("evidence-owner-" + suffix, "evidence-" + suffix + "@example.invalid",
             "salt", "hash", timestamp),
        )
        connection.execute(
            """
            INSERT INTO external_adapter_certifications (
                id, provider_id, adapter_id, adapter_version, provider_scope,
                tool_id, tool_contract_fingerprint, capabilities_json,
                test_suite_version, conformance_results_json, test_report_sha256,
                evidence_references_json, verified_at, expires_at, approved_by,
                created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("cert-" + suffix, "provider", "adapter", "1.0", "scope", "tool",
             "a" * 64, "[]", "suite-1", "{}", "b" * 64, "[]",
             timestamp, "2027-01-01T00:00:00+00:00", "operator", timestamp),
        )
        connection.execute(
            """
            INSERT INTO external_adapter_certification_revocations (
                id, certification_id, revoked_by, reason, created_at
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            ("cert-revoke-" + suffix, "cert-" + suffix, "operator",
             "test revocation", timestamp),
        )
        connection.execute(
            """
            INSERT INTO external_adapter_evidence_packages (
                id, provider_id, adapter_id, adapter_version, provider_scope,
                tool_id, tool_contract_fingerprint, capabilities_json,
                test_suite_version, sandbox_environment, manifest_json,
                manifest_sha256, artifact_hashes_json, conformance_results_json,
                executed_at, verified_at, expires_at, provenance, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("package-" + suffix, "provider", "adapter", "1.0", "scope", "tool",
             "a" * 64, "[]", "suite-1", "isolated", "{}", "c" * 64, "{}",
             "{}", timestamp, timestamp, "2027-01-01T00:00:00+00:00",
             "unattested", timestamp),
        )
        connection.execute(
            """
            INSERT INTO external_adapter_evidence_artifacts (
                id, package_id, artifact_name, sha256, content
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            ("artifact-" + suffix, "package-" + suffix, "report.json",
             "d" * 64, b'{"ok":true}'),
        )
        connection.execute(
            """
            INSERT INTO trusted_runner_keys (
                key_id, runner_id, provider_id, adapter_id, adapter_version,
                provider_scope, tool_id, tool_contract_fingerprint, algorithm,
                public_key, valid_from, valid_until, registered_by, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("runner-key-" + suffix, "runner", "provider", "adapter", "1.0",
             "scope", "tool", "a" * 64, "Ed25519", runner_public_key,
             "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00",
             "operator", timestamp),
        )
        connection.execute(
            """
            INSERT INTO external_adapter_evidence_attestations (
                id, package_id, key_id, runner_id, nonce, payload_json,
                payload_sha256, signature, verified_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("attestation-" + suffix, "package-" + suffix, "runner-key-" + suffix,
             "runner", "nonce-" + suffix, "{}", "e" * 64, "signature", timestamp),
        )
        connection.execute(
            """
            INSERT INTO security_operator_audit_events (
                id, actor_user_id, actor_email, action, target_type, target_id,
                outcome, details_json, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            ("operator-audit-" + suffix, "evidence-owner-" + suffix,
             "operator@example.invalid", "evidence.approve", "certification",
             "cert-" + suffix, "succeeded", "{}", timestamp),
        )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "UPDATE external_adapter_certifications SET approved_by=%s WHERE id=%s",
                    ("tampered", "cert-" + suffix),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "UPDATE external_adapter_evidence_artifacts SET content=%s WHERE id=%s",
                    (b"tampered", "artifact-" + suffix),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "DELETE FROM trusted_runner_keys WHERE key_id=%s",
                    ("runner-key-" + suffix,),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "DELETE FROM security_operator_audit_events WHERE id=%s",
                    ("operator-audit-" + suffix,),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO trusted_runner_keys (
                        key_id, runner_id, provider_id, adapter_id, adapter_version,
                        provider_scope, tool_id, tool_contract_fingerprint, algorithm,
                        public_key, valid_from, valid_until, registered_by, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("invalid-key-" + suffix, "runner", "provider", "adapter",
                     "1.0", "scope", "tool", "a" * 64, "Ed25519", b"short",
                     timestamp, "2027-01-01T00:00:00+00:00", "operator", timestamp),
                )
