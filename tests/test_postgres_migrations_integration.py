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
    assert runner.migrate() == 35
    assert runner.migrate() == 35

    user_id = str(uuid.uuid4())
    deleted_user_id = str(uuid.uuid4())
    email = f"postgres-migration-{user_id}@example.invalid"
    deleted_email = f"postgres-deleted-{deleted_user_id}@example.invalid"
    request_id = "request-" + user_id
    credential_id = "credential-" + user_id
    challenge_id = "challenge-" + user_id
    recovery_id = "recovery-" + user_id
    authorization_id = "authorization-" + user_id
    consent_id = "consent-" + user_id
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
                INSERT INTO memory_consents (
                    id, user_id, purpose, policy_version, retention_days,
                    granted_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (consent_id, user_id, "personal_memory", 1, 365, timestamp),
            )
            connection.execute(
                """
                INSERT INTO memory_items (
                    id, user_id, memory_type, key, value_json, source,
                    confidence, status, created_at, updated_at, consent_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                ("memory-" + user_id, user_id, "preference", "theme", '"dark"',
                 "user", 1.0, "active", timestamp, timestamp, consent_id),
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
            connection.execute("DELETE FROM memory_consents WHERE id=%s", (consent_id,))
            connection.execute("DELETE FROM sessions WHERE token_hash=%s", ("token-" + user_id,))
            connection.execute("UPDATE users SET deleted_at=%s WHERE id=%s", (timestamp, user_id))
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
            (12, "memory_consent_lifecycle_and_memory_binding"),
            (13, "learning_adaptation_events_and_evaluations"),
            (14, "agent_identity_and_registration_events"),
            (15, "agent_lifecycle_event_guards"),
            (16, "agent_capability_grants_tasks_messages_and_controls"),
            (17, "agent_task_transition_and_definition_guards"),
            (18, "agent_runs_steps_and_event_history"),
            (19, "integration_connections_grants_and_events"),
            (20, "integration_secret_vault_and_terminal_erasure"),
            (21, "agent_run_integration_bindings"),
            (22, "agent_run_integration_dispatch_lifecycle"),
            (23, "agent_capability_text_generation"),
            (24, "device_registry"),
            (25, "device_public_keys_and_auth_challenges"),
            (26, "device_session_binding_schema"),
            (27, "device_security_events_initial"),
            (28, "device_security_event_history_and_atomic_audit"),
            (29, "device_identity_and_lifecycle_guards"),
            (30, "session_device_binding_and_revocation_guards"),
            (31, "session_security_audit_history"),
            (32, "device_key_rotation_challenges"),
            (33, "recovery_code_authorized_device_rotation"),
            (34, "recovery_security_notification_outbox"),
            (35, "security_notification_dead_letter_state"),
        ]



def test_real_postgres_external_evidence_and_operator_audit_are_immutable():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 35

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


def test_real_postgres_dispatch_recovery_lookup_and_reconciliation_guards():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 35

    suffix = str(uuid.uuid4())
    user_id = "dispatch-owner-" + suffix
    email = "dispatch-" + suffix + "@example.invalid"
    recovery_request = "recovery-request-" + suffix
    lookup_request = "lookup-request-" + suffix
    digest = "f" * 64
    timestamp = "2026-01-01T00:00:00+00:00"
    future = "2027-01-01T00:00:00+00:00"

    with psycopg.connect(database_url) as connection:
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO users (id, email, password_salt, password_hash, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, email, "salt", "hash", timestamp),
            )

            # A request claimed for execution but with no dispatch_started event
            # can receive exactly one dispatch_not_started recovery record.
            connection.execute(
                """
                INSERT INTO tool_requests (
                    id, user_id, tool_id, arguments_json, status, consumed_at,
                    created_at, updated_at
                ) VALUES (%s, %s, %s, %s, 'executing', %s, %s, %s)
                """,
                (recovery_request, user_id, "external.test", "{}", timestamp,
                 timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key, status,
                    claimed_at, updated_at
                ) VALUES (%s, %s, %s, %s, 'claimed', %s, %s)
                """,
                ("recovery-attempt-" + suffix, user_id, recovery_request,
                 recovery_request, timestamp, timestamp),
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
                ("recovery-binding-" + suffix, user_id, recovery_request,
                 recovery_request, digest, "{}", "a" * 64, "adapter", "1",
                 "provider", "scope", "[]", timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_dispatch_recovery_events (
                    id, user_id, request_id, event_type, action_digest,
                    details_json, created_at
                ) VALUES (%s, %s, %s, 'dispatch_not_started', %s, %s, %s)
                """,
                ("recovery-event-" + suffix, user_id, recovery_request,
                 digest, "{}", timestamp),
            )

            # A started dispatch that becomes outcome-unknown can be given a
            # current certification-bound lookup authorization and one
            # immutable human reconciliation record.
            connection.execute(
                """
                INSERT INTO tool_requests (
                    id, user_id, tool_id, arguments_json, status, consumed_at,
                    created_at, updated_at
                ) VALUES (%s, %s, %s, %s, 'executing', %s, %s, %s)
                """,
                (lookup_request, user_id, "external.test", "{}", timestamp,
                 timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key, status,
                    claimed_at, updated_at
                ) VALUES (%s, %s, %s, %s, 'claimed', %s, %s)
                """,
                ("lookup-attempt-" + suffix, user_id, lookup_request,
                 lookup_request, timestamp, timestamp),
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
                ("lookup-binding-" + suffix, user_id, lookup_request,
                 lookup_request, digest, "{}", "b" * 64, "adapter", "1",
                 "provider", "scope", "[]", timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_dispatch_audit_events (
                    id, user_id, request_id, event_type, action_digest,
                    details_json, created_at
                ) VALUES (%s, %s, %s, 'dispatch_started', %s, %s, %s)
                """,
                ("lookup-start-" + suffix, user_id, lookup_request,
                 digest, "{}", timestamp),
            )
            connection.execute(
                "UPDATE tool_requests SET status='outcome_unknown' WHERE id=%s",
                (lookup_request,),
            )
            connection.execute(
                """
                UPDATE tool_execution_attempts
                SET status='outcome_unknown', finished_at=%s, updated_at=%s
                WHERE request_id=%s
                """,
                (timestamp, timestamp, lookup_request),
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
                ("lookup-cert-" + suffix, "provider", "adapter", "1", "scope",
                 "external.test", "b" * 64, "[]", "suite", "{}", "c" * 64,
                 "[]", timestamp, future, "operator", timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_dispatch_lookup_authorizations (
                    id, user_id, request_id, certification_id, action_digest,
                    details_json, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("lookup-auth-" + suffix, user_id, lookup_request,
                 "lookup-cert-" + suffix, digest, "{}", timestamp),
            )
            connection.execute(
                """
                INSERT INTO tool_execution_reconciliation_events (
                    id, user_id, request_id, outcome, note, error_code, created_at
                ) VALUES (%s, %s, %s, 'succeeded', %s, NULL, %s)
                """,
                ("reconciliation-" + suffix, user_id, lookup_request,
                 "Verified completion with the external provider.", timestamp),
            )

        for table, column, value in (
            ("tool_dispatch_recovery_events", "id", "recovery-event-" + suffix),
            ("tool_dispatch_lookup_authorizations", "id", "lookup-auth-" + suffix),
            ("tool_execution_reconciliation_events", "id", "reconciliation-" + suffix),
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                with connection.transaction():
                    connection.execute(
                        f"UPDATE {table} SET created_at=%s WHERE {column}=%s",
                        (future, value),
                    )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO tool_dispatch_recovery_events (
                        id, user_id, request_id, event_type, action_digest,
                        details_json, created_at
                    ) VALUES (%s, %s, %s, 'dispatch_not_started', %s, %s, %s)
                    """,
                    ("duplicate-recovery-" + suffix, user_id, recovery_request,
                     digest, "{}", timestamp),
                )

        with connection.transaction():
            connection.execute(
                "UPDATE users SET deleted_at=%s WHERE id=%s",
                (timestamp, user_id),
            )
            connection.execute("DELETE FROM tool_requests WHERE user_id=%s", (user_id,))
            connection.execute("DELETE FROM users WHERE id=%s", (user_id,))


def test_real_postgres_memory_consent_and_learning_history_guards():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 35

    suffix = str(uuid.uuid4())
    user_id = "memory-learning-owner-" + suffix
    adaptation_id = "adaptation-learning-" + suffix
    pending_adaptation_id = "adaptation-pending-" + suffix
    consent_id = "memory-consent-" + suffix
    replacement_consent_id = "memory-consent-replacement-" + suffix
    timestamp = "2026-01-01T00:00:00+00:00"
    future = "2027-01-01T00:00:00+00:00"

    with psycopg.connect(database_url) as connection:
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO users (id, email, password_salt, password_hash, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, user_id + "@example.invalid", "salt", "hash", timestamp),
            )
            connection.execute(
                """
                INSERT INTO adaptations (
                    id, user_id, proposal_json, status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (adaptation_id, user_id, '{"change":"safe"}', "pending", timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO adaptations (
                    id, user_id, proposal_json, status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (pending_adaptation_id, user_id, '{"change":"not-approved"}',
                 "pending", timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO memory_consents (
                    id, user_id, purpose, policy_version, retention_days, granted_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (consent_id, user_id, "personal_memory", 1, 90, timestamp),
            )
            connection.execute(
                """
                INSERT INTO memory_items (
                    id, user_id, memory_type, key, value_json, source,
                    confidence, status, created_at, updated_at, consent_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                ("memory-" + suffix, user_id, "preference", "theme", '"dark"',
                 "user", 1.0, "active", timestamp, timestamp, consent_id),
            )

        with pytest.raises(psycopg.errors.UniqueViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO memory_consents (
                        id, user_id, purpose, policy_version, retention_days, granted_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    ("duplicate-consent-" + suffix, user_id,
                     "personal_memory", 1, 30, timestamp),
                )

        with connection.transaction():
            connection.execute(
                "UPDATE memory_consents SET retention_days=%s WHERE id=%s",
                (180, consent_id),
            )
            connection.execute(
                "UPDATE memory_consents SET revoked_at=%s WHERE id=%s",
                (timestamp, consent_id),
            )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "UPDATE memory_consents SET revoked_at=NULL WHERE id=%s",
                    (consent_id,),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "UPDATE memory_consents SET retention_days=%s WHERE id=%s",
                    (365, consent_id),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "DELETE FROM memory_consents WHERE id=%s",
                    (consent_id,),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "UPDATE memory_items SET status=%s WHERE id=%s",
                    ("archived", "memory-" + suffix),
                )

        with connection.transaction():
            connection.execute(
                """
                INSERT INTO memory_consents (
                    id, user_id, purpose, policy_version, retention_days, granted_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (replacement_consent_id, user_id, "personal_memory", 1, 365, future),
            )
            connection.execute(
                "UPDATE memory_items SET consent_id=%s WHERE id=%s",
                (replacement_consent_id, "memory-" + suffix),
            )
            connection.execute(
                "UPDATE adaptations SET status=%s WHERE id=%s",
                ("approved", adaptation_id),
            )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "UPDATE adaptations SET status=%s WHERE id=%s",
                    ("pending", adaptation_id),
                )

        event_id = "learning-event-" + suffix
        evaluation_id = "learning-evaluation-" + suffix
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO learning_adaptation_events (
                    id, user_id, adaptation_id, event_type, details_json, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (event_id, user_id, adaptation_id, "approved", '{"source":"user"}', timestamp),
            )
            connection.execute(
                """
                INSERT INTO learning_evaluations (
                    id, user_id, adaptation_id, outcome, metric, baseline_value,
                    observed_value, confidence, evidence_json, source, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (evaluation_id, user_id, adaptation_id, "improved", "task_success",
                 0.5, 0.8, 0.9, '{"sample_count":3}', "user_reported", future),
            )

        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO learning_evaluations (
                        id, user_id, adaptation_id, outcome, metric, baseline_value,
                        observed_value, confidence, evidence_json, source, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("invalid-evaluation-" + suffix, user_id, pending_adaptation_id,
                     "improved", "task_success", 0.5, 0.8, 0.9, "{}",
                     "user_reported", future),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "UPDATE learning_adaptation_events SET details_json=%s WHERE id=%s",
                    ('{"tampered":true}', event_id),
                )
        with pytest.raises(psycopg.errors.CheckViolation):
            with connection.transaction():
                connection.execute(
                    "DELETE FROM learning_evaluations WHERE id=%s",
                    (evaluation_id,),
                )

        with connection.transaction():
            connection.execute(
                "UPDATE users SET deleted_at=%s WHERE id=%s",
                (future, user_id),
            )
            connection.execute(
                "DELETE FROM learning_adaptation_events WHERE id=%s",
                (event_id,),
            )
            connection.execute(
                "DELETE FROM learning_evaluations WHERE id=%s",
                (evaluation_id,),
            )
            connection.execute(
                "DELETE FROM memory_items WHERE id=%s",
                ("memory-" + suffix,),
            )
            connection.execute(
                "DELETE FROM memory_consents WHERE user_id=%s",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM adaptations WHERE user_id=%s",
                (user_id,),
            )
            connection.execute("DELETE FROM users WHERE id=%s", (user_id,))


def test_real_postgres_agent_lifecycle_capability_and_run_guards():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    assert PostgresMigrationRunner(database_url).migrate() == 35
    suffix = str(uuid.uuid4())
    owner = "agent-owner-" + suffix
    other = "agent-other-" + suffix
    agent = "agent-" + suffix
    grant = "grant-" + suffix
    task = "task-" + suffix
    run = "run-" + suffix
    step = "step-" + suffix
    timestamp = "2026-01-01T00:00:00+00:00"
    future = "2027-01-01T00:00:00+00:00"

    class RollbackFixture(Exception):
        pass

    with psycopg.connect(database_url) as connection:
        try:
            with connection.transaction():
                for user_id, email in (
                    (owner, owner + "@example.invalid"),
                    (other, other + "@example.invalid"),
                ):
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
                    INSERT INTO agents (
                        id, user_id, name, metadata_json, status, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (agent, owner, "Research agent", "{}", "draft", timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_events (
                        id, user_id, agent_id, actor_user_id, event_type,
                        details_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("registered-" + suffix, owner, agent, owner, "registered",
                     '{"initial_status":"draft"}', timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_events (
                        id, user_id, agent_id, actor_user_id, event_type,
                        details_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("activated-" + suffix, owner, agent, owner, "activated",
                     '{"from_status":"draft","to_status":"active"}', timestamp),
                )
                connection.execute(
                    "UPDATE agents SET status='active', updated_at=%s WHERE id=%s",
                    (timestamp, agent),
                )
                connection.execute(
                    """
                    INSERT INTO agent_capability_grants (
                        id, user_id, agent_id, capability, expires_at, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (grant, owner, agent, "notes.read", future, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_tasks (
                        id, user_id, agent_id, title, goal, context_json,
                        capability_ceiling_json, status, expires_at, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (task, owner, agent, "Prepare notes", "Research a topic", "{}",
                     '["notes.read"]', "assigned", future, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_task_events (
                        id, user_id, task_id, actor_user_id, event_type,
                        details_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("assigned-" + suffix, owner, task, owner, "assigned",
                     '{"to_status":"assigned"}', timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_task_events (
                        id, user_id, task_id, actor_user_id, event_type,
                        details_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("in-progress-" + suffix, owner, task, owner, "in_progress",
                     '{"from_status":"assigned","to_status":"in_progress"}', timestamp),
                )
                connection.execute(
                    "UPDATE agent_tasks SET status='in_progress', updated_at=%s WHERE id=%s",
                    (timestamp, task),
                )
                connection.execute(
                    """
                    INSERT INTO agent_messages (
                        id, user_id, sender_agent_id, recipient_agent_id,
                        task_id, payload_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("message-" + suffix, owner, agent, agent, task,
                     '{"kind":"status"}', timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_runs (
                        id, user_id, agent_id, task_id, actions_json, plan_digest,
                        status, expires_at, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (run, owner, agent, task, '[{"tool_id":"notes.read"}]',
                     "a" * 64, "proposed", future, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_events (
                        id, user_id, run_id, actor_user_id, event_type,
                        details_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("authorize-" + suffix, owner, run, owner, "authorized",
                     '{"from_status":"proposed","to_status":"authorized"}', timestamp),
                )
                connection.execute(
                    "UPDATE agent_runs SET status='authorized', authorized_at=%s WHERE id=%s",
                    (timestamp, run),
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_steps (
                        id, user_id, run_id, ordinal, tool_id, arguments_json,
                        contract_fingerprint, required_capability, status,
                        created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (step, owner, run, 0, "notes.read", "{}", "b" * 64,
                     "notes.read", "pending", timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_events (
                        id, user_id, run_id, actor_user_id, event_type,
                        details_json, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    ("step-start-" + suffix, owner, run, owner, "step_started",
                     '{"step_id":"' + step + '"}', timestamp),
                )
                connection.execute(
                    "UPDATE agent_run_steps SET status='running', updated_at=%s WHERE id=%s",
                    (timestamp, step),
                )

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            INSERT INTO agent_tasks (
                                id, user_id, agent_id, title, goal, context_json,
                                capability_ceiling_json, status, expires_at, created_at, updated_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            ("bad-task-" + suffix, owner, agent, "Escalated",
                             "Use ungranted capability", "{}", '["calendar.write"]',
                             "assigned", future, timestamp, timestamp),
                        )

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            "UPDATE agent_run_steps SET tool_id='tampered' WHERE id=%s",
                            (step,),
                        )

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("DELETE FROM agents WHERE id=%s", (agent,))

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            INSERT INTO agent_capability_grants (
                                id, user_id, agent_id, capability, created_at
                            ) VALUES (%s, %s, %s, %s, %s)
                            """,
                            ("foreign-grant-" + suffix, other, agent, "notes.read", timestamp),
                        )
                raise RollbackFixture()
        except RollbackFixture:
            pass



def test_real_postgres_integration_connection_vault_and_agent_dispatch_guards():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    assert PostgresMigrationRunner(database_url).migrate() == 35
    suffix = str(uuid.uuid4())
    owner = "integration-owner-" + suffix
    other = "integration-other-" + suffix
    agent = "integration-agent-" + suffix
    task = "integration-task-" + suffix
    run = "integration-run-" + suffix
    step = "integration-step-" + suffix
    connection_id = "integration-connection-" + suffix
    secret_ref = "integration-secret-" + suffix
    grant_id = "integration-grant-" + suffix
    timestamp = "2026-01-01T00:00:00+00:00"
    future = "2027-01-01T00:00:00+00:00"

    class RollbackFixture(Exception):
        pass

    with psycopg.connect(database_url) as connection:
        try:
            with connection.transaction():
                for user_id in (owner, other):
                    connection.execute(
                        """
                        INSERT INTO users (id,email,password_salt,password_hash,created_at)
                        VALUES (%s,%s,%s,%s,%s)
                        """,
                        (user_id, user_id + "@example.invalid", "salt", "hash", timestamp),
                    )
                connection.execute(
                    """
                    INSERT INTO agents (
                        id,user_id,name,metadata_json,status,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (agent, owner, "Integration agent", "{}", "draft", timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_events (
                        id,user_id,agent_id,actor_user_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    ("registered-" + suffix, owner, agent, owner, "registered",
                     '{"initial_status":"draft"}', timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_events (
                        id,user_id,agent_id,actor_user_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    ("activated-" + suffix, owner, agent, owner, "activated",
                     '{"from_status":"draft","to_status":"active"}', timestamp),
                )
                connection.execute(
                    "UPDATE agents SET status='active',updated_at=%s WHERE id=%s",
                    (timestamp, agent),
                )
                connection.execute(
                    """
                    INSERT INTO agent_tasks (
                        id,user_id,agent_id,title,goal,context_json,capability_ceiling_json,
                        status,expires_at,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (task, owner, agent, "Use calendar", "Read calendar", "{}",
                     '[]', "assigned", future, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_task_events (
                        id,user_id,task_id,actor_user_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    ("task-assigned-" + suffix, owner, task, owner, "assigned",
                     '{"to_status":"assigned"}', timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_runs (
                        id,user_id,agent_id,task_id,actions_json,plan_digest,status,
                        expires_at,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (run, owner, agent, task, '[{"tool_id":"calendar.read"}]',
                     "a" * 64, "proposed", future, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_steps (
                        id,user_id,run_id,ordinal,tool_id,arguments_json,
                        contract_fingerprint,required_capability,status,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (step, owner, run, 0, "calendar.read", "{}", "b" * 64,
                     None, "pending", timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO integration_connections (
                        id,user_id,integration_id,status,consent_version,consented_at,
                        secret_ref,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (connection_id, owner, "calendar", "pending_verification",
                     "v1", timestamp, secret_ref, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO integration_connection_grants (
                        id,user_id,connection_id,scope,status,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    (grant_id, owner, connection_id, "calendar.read", "pending", timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO integration_secrets (
                        secret_ref,user_id,connection_id,integration_id,nonce,
                        ciphertext,key_version,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (secret_ref, owner, connection_id, "calendar", b"n" * 12,
                     b"c" * 32, 1, timestamp, timestamp),
                )
                connection.execute(
                    """
                    UPDATE integration_connections
                    SET status='active',verified_at=%s,updated_at=%s
                    WHERE id=%s
                    """,
                    (timestamp, timestamp, connection_id),
                )
                connection.execute(
                    "UPDATE integration_connection_grants SET status='active' WHERE id=%s",
                    (grant_id,),
                )
                connection.execute(
                    """
                    INSERT INTO integration_connection_events (
                        id,user_id,connection_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    ("connection-event-" + suffix, owner, connection_id,
                     "verified", '{"verification":"passed"}', timestamp),
                )

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            INSERT INTO integration_connection_grants (
                                id,user_id,connection_id,scope,status,created_at
                            ) VALUES (%s,%s,%s,%s,%s,%s)
                            """,
                            ("foreign-grant-" + suffix, other, connection_id,
                             "calendar.write", "pending", timestamp),
                        )

                connection.execute(
                    """
                    INSERT INTO agent_run_integration_bindings (
                        step_id,user_id,run_id,connection_id,integration_id,
                        manifest_version,tool_id,contract_fingerprint,
                        required_scopes_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (step, owner, run, connection_id, "calendar", "1",
                     "calendar.read", "b" * 64, '["calendar.read"]', timestamp),
                )

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            UPDATE agent_run_integration_bindings
                            SET tool_id='calendar.write' WHERE step_id=%s
                            """,
                            (step,),
                        )
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            INSERT INTO agent_run_integration_bindings (
                                step_id,user_id,run_id,connection_id,integration_id,
                                manifest_version,tool_id,contract_fingerprint,
                                required_scopes_json,created_at
                            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """,
                            (step, owner, run, connection_id,
                             "calendar", "1", "calendar.read", "b" * 64,
                             '["calendar.write"]', timestamp),
                        )

                connection.execute(
                    """
                    INSERT INTO agent_run_events (
                        id,user_id,run_id,actor_user_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    ("run-start-" + suffix, owner, run, owner, "started",
                     '{"from_status":"proposed","to_status":"running"}', timestamp),
                )
                connection.execute(
                    "UPDATE agent_runs SET status='running',started_at=%s WHERE id=%s",
                    (timestamp, run),
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_events (
                        id,user_id,run_id,actor_user_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    ("step-start-" + suffix, owner, run, owner, "step_started",
                     '{"step_id":"' + step + '"}', timestamp),
                )
                connection.execute(
                    "UPDATE agent_run_steps SET status='running' WHERE id=%s", (step,)
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_events (
                        id,user_id,run_id,actor_user_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    ("dispatch-start-" + suffix, owner, run, owner,
                     "integration_dispatch_started", '{"step_id":"' + step + '"}', timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_integration_dispatches (
                        step_id,user_id,run_id,connection_id,integration_id,tool_id,
                        contract_fingerprint,status,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (step, owner, run, connection_id, "calendar", "calendar.read",
                     "b" * 64, "prepared", timestamp, timestamp),
                )
                connection.execute(
                    """
                    UPDATE agent_run_integration_dispatches
                    SET status='dispatch_started',dispatch_started_at=%s,updated_at=%s
                    WHERE step_id=%s
                    """,
                    (timestamp, timestamp, step),
                )
                connection.execute(
                    """
                    INSERT INTO agent_run_events (
                        id,user_id,run_id,actor_user_id,event_type,details_json,created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    ("dispatch-done-" + suffix, owner, run, owner,
                     "integration_dispatch_succeeded", '{"step_id":"' + step + '"}', future),
                )
                connection.execute(
                    """
                    UPDATE agent_run_integration_dispatches
                    SET status='succeeded',finished_at=%s,outcome_json=%s,updated_at=%s
                    WHERE step_id=%s
                    """,
                    (future, '{"events":2}', future, step),
                )

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            UPDATE agent_run_integration_dispatches
                            SET outcome_json=%s WHERE step_id=%s
                            """,
                            ('{"tampered":true}', step),
                        )

                # Terminal connection revocation atomically destroys its vault secret.
                connection.execute(
                    "UPDATE integration_connections SET status='revoked',updated_at=%s WHERE id=%s",
                    (future, connection_id),
                )
                assert connection.execute(
                    "SELECT count(*) FROM integration_secrets WHERE connection_id=%s",
                    (connection_id,),
                ).fetchone()[0] == 0

                erasure_connection = "erasure-connection-" + suffix
                erasure_secret = "erasure-secret-" + suffix
                connection.execute(
                    """
                    INSERT INTO integration_connections (
                        id,user_id,integration_id,status,consent_version,consented_at,
                        secret_ref,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (erasure_connection, owner, "calendar", "pending_verification",
                     "v1", timestamp, erasure_secret, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO integration_secrets (
                        secret_ref,user_id,connection_id,integration_id,nonce,
                        ciphertext,key_version,created_at,updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (erasure_secret, owner, erasure_connection, "calendar",
                     b"z" * 12, b"v" * 32, 1, timestamp, timestamp),
                )
                connection.execute("UPDATE users SET deleted_at=%s WHERE id=%s", (future, owner))
                connection.execute("DELETE FROM users WHERE id=%s", (owner,))
                assert connection.execute(
                    "SELECT count(*) FROM integration_secrets WHERE secret_ref=%s",
                    (erasure_secret,),
                ).fetchone()[0] == 0
                connection.execute("UPDATE users SET deleted_at=%s WHERE id=%s", (future, other))
                connection.execute("DELETE FROM users WHERE id=%s", (other,))
                raise RollbackFixture()
        except RollbackFixture:
            pass


def test_real_postgres_device_foundation_migrations_preserve_owner_and_challenge_rules():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 35
    assert runner.migrate() == 35

    owner = str(uuid.uuid4())
    email = f"postgres-device-{owner}@example.invalid"
    timestamp = "2026-01-01T00:00:00+00:00"
    future = "2027-01-01T00:00:00+00:00"
    device_id = "device-" + owner

    class RollbackFixture(Exception):
        pass

    try:
        with psycopg.connect(database_url) as connection:
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO users (id,email,password_salt,password_hash,created_at)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (owner,email,"salt","hash",timestamp),
                )
                agent = "agent-" + owner
                connection.execute(
                    """
                    INSERT INTO agents (id,user_id,name,status,created_at,updated_at)
                    VALUES (%s,%s,%s,'draft',%s,%s)
                    """,
                    (agent,owner,"Device test agent",timestamp,timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_events
                        (id,user_id,agent_id,actor_user_id,event_type,details_json,created_at)
                    VALUES (%s,%s,%s,%s,'registered',%s,%s)
                    """,
                    ("agent-registered-"+owner,owner,agent,owner,
                     '{"initial_status":"draft"}',timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agent_events
                        (id,user_id,agent_id,actor_user_id,event_type,details_json,created_at)
                    VALUES (%s,%s,%s,%s,'activated',%s,%s)
                    """,
                    ("agent-activated-"+owner,owner,agent,owner,
                     '{"from_status":"draft","to_status":"active"}',timestamp),
                )
                connection.execute(
                    "UPDATE agents SET status='active',updated_at=%s WHERE id=%s",
                    (timestamp,agent),
                )
                connection.execute(
                    """
                    INSERT INTO agent_capability_grants
                        (id,user_id,agent_id,capability,created_at)
                    VALUES (%s,%s,%s,'text_generation',%s)
                    """,
                    ("grant-"+owner,owner,agent,timestamp),
                )

                connection.execute(
                    """
                    INSERT INTO devices (
                        id,user_id,platform,app_version,display_name,
                        public_key_fingerprint,status,enrolled_at
                    ) VALUES (%s,%s,'android','1.0','Test device',%s,'pending',%s)
                    """,
                    (device_id,owner,"a"*64,timestamp),
                )
                connection.execute(
                    "UPDATE devices SET public_key_b64=%s WHERE id=%s",
                    ("cHVibGljLWtleQ==",device_id),
                )
                enrollment_challenge = "enrollment-" + owner
                connection.execute(
                    """
                    INSERT INTO device_auth_challenges
                        (id,device_id,user_id,nonce_hash,expires_at,created_at)
                    VALUES (%s,%s,%s,%s,%s,%s)
                    """,
                    (enrollment_challenge,device_id,owner,"b"*64,future,timestamp),
                )
                connection.execute(
                    "UPDATE devices SET status='active' WHERE id=%s", (device_id,)
                )
                session_challenge = "session-" + owner
                connection.execute(
                    """
                    INSERT INTO device_auth_challenges
                        (id,device_id,user_id,nonce_hash,expires_at,created_at,purpose)
                    VALUES (%s,%s,%s,%s,%s,%s,'session')
                    """,
                    (session_challenge,device_id,owner,"d"*64,future,timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO sessions
                        (token_hash,user_id,expires_at,created_at,device_id,auth_method)
                    VALUES (%s,%s,%s,%s,%s,'device_proof')
                    """,
                    ("device-session-"+owner,owner,future,timestamp,device_id),
                )
                row = connection.execute(
                    "SELECT device_id,auth_method FROM sessions WHERE token_hash=%s",
                    ("device-session-"+owner,),
                ).fetchone()
                assert tuple(row) == (device_id,"device_proof")

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            INSERT INTO device_auth_challenges
                                (id,device_id,user_id,nonce_hash,expires_at,created_at,purpose)
                            VALUES (%s,%s,%s,%s,%s,%s,'invalid')
                            """,
                            ("bad-purpose-"+owner,device_id,owner,"e"*64,future,timestamp),
                        )
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            INSERT INTO agent_capability_grants
                                (id,user_id,agent_id,capability,created_at)
                            VALUES (%s,%s,%s,'invalid.capability',%s)
                            """,
                            ("bad-capability-"+owner,owner,agent,timestamp),
                        )
                raise RollbackFixture()
    except RollbackFixture:
        pass


def test_real_postgres_device_security_audit_lifecycle_and_session_guards():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")
    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 35
    assert runner.migrate() == 35
    owner = str(uuid.uuid4())
    timestamp = "2026-01-01T00:00:00+00:00"
    future = "2027-01-01T00:00:00+00:00"
    device_id = "device-audit-" + owner

    class RollbackFixture(Exception):
        pass

    try:
        with psycopg.connect(database_url) as connection:
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO users (id,email,password_salt,password_hash,created_at)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (owner,f"postgres-device-audit-{owner}@example.invalid","salt","hash",timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO devices (
                        id,user_id,platform,app_version,public_key_fingerprint,status,enrolled_at
                    ) VALUES (%s,%s,'android','1.0',%s,'pending',%s)
                    """,
                    (device_id,owner,"a"*64,timestamp),
                )
                connection.execute("UPDATE devices SET public_key_b64=%s WHERE id=%s",("cHVibGljLWtleQ==",device_id))
                connection.execute("UPDATE devices SET status='active' WHERE id=%s",(device_id,))
                connection.execute(
                    """
                    INSERT INTO sessions (token_hash,user_id,expires_at,created_at,device_id,auth_method)
                    VALUES (%s,%s,%s,%s,%s,'device_login')
                    """,
                    ("audit-session-"+owner,owner,future,timestamp,device_id),
                )
                event_types = [r[0] for r in connection.execute(
                    "SELECT event_type FROM device_security_events WHERE user_id=%s ORDER BY occurred_at,id",
                    (owner,),
                ).fetchall()]
                assert set(event_types) == {
                    "device.enrolled","device.key_registered","device.activated",
                    "device.login_authenticated",
                }
                assert len(event_types) == 4

                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("UPDATE device_security_events SET details_json='{}' WHERE user_id=%s",(owner,))
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("DELETE FROM device_security_events WHERE user_id=%s",(owner,))
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("UPDATE devices SET id=%s WHERE id=%s",("renamed-"+owner,device_id))
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("UPDATE devices SET public_key_b64=%s WHERE id=%s",("bmV3LWtleQ==",device_id))
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("UPDATE devices SET status='pending' WHERE id=%s",(device_id,))
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            """
                            INSERT INTO sessions (token_hash,user_id,expires_at,created_at,device_id,auth_method)
                            VALUES (%s,%s,%s,%s,%s,'account')
                            """,
                            ("bad-binding-"+owner,owner,future,timestamp,device_id),
                        )
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("UPDATE sessions SET expires_at=%s WHERE token_hash=%s",(future+" ","audit-session-"+owner))
                connection.execute("UPDATE sessions SET revoked_at=%s WHERE token_hash=%s",(future,"audit-session-"+owner))
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute("UPDATE sessions SET revoked_at=NULL WHERE token_hash=%s",("audit-session-"+owner,))

                connection.execute("UPDATE devices SET status='revoked' WHERE id=%s",(device_id,))
                assert connection.execute(
                    "SELECT count(*) FROM device_security_events WHERE user_id=%s AND event_type='device.revoked'",
                    (owner,),
                ).fetchone()[0] == 1
                count_before = connection.execute("SELECT count(*) FROM device_security_events WHERE user_id=%s",(owner,)).fetchone()[0]
                connection.execute("DELETE FROM devices WHERE id=%s",(device_id,))
                assert connection.execute("SELECT count(*) FROM device_security_events WHERE user_id=%s",(owner,)).fetchone()[0] == count_before

                connection.execute("UPDATE users SET deleted_at=%s WHERE id=%s",(future,owner))
                connection.execute("DELETE FROM users WHERE id=%s",(owner,))
                assert connection.execute("SELECT count(*) FROM device_security_events WHERE user_id=%s",(owner,)).fetchone()[0] == 0
                raise RollbackFixture()
    except RollbackFixture:
        pass


def test_real_postgres_session_audit_device_rotation_and_recovery_outbox():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")
    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 35
    assert runner.migrate() == 35
    owner = str(uuid.uuid4())
    timestamp = "2026-01-01T00:00:00+00:00"
    future = "2027-01-01T00:00:00+00:00"
    device_id = "rotation-device-" + owner

    class RollbackFixture(Exception):
        pass

    try:
        with psycopg.connect(database_url) as connection:
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO users (id,email,password_salt,password_hash,created_at)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (owner,f"postgres-rotation-{owner}@example.invalid","salt","hash",timestamp),
                )
                # Account-session audit references are generated by the database.
                token = "session-audit-" + owner
                connection.execute(
                    """
                    INSERT INTO sessions (token_hash,user_id,expires_at,created_at)
                    VALUES (%s,%s,%s,%s)
                    """,
                    (token,owner,future,timestamp),
                )
                audit_ref = connection.execute(
                    "SELECT audit_ref FROM sessions WHERE token_hash=%s",(token,)
                ).fetchone()[0]
                assert audit_ref
                assert connection.execute(
                    "SELECT event_type FROM session_security_events WHERE session_ref=%s",
                    (audit_ref,),
                ).fetchone()[0] == "session.created"
                connection.execute(
                    "UPDATE sessions SET revoked_at=%s WHERE token_hash=%s",(future,token)
                )
                assert connection.execute(
                    "SELECT event_type FROM session_security_events WHERE session_ref=%s ORDER BY event_type",
                    (audit_ref,),
                ).fetchall() == [("session.created",),("session.revoked",)]
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            "UPDATE session_security_events SET occurred_at=%s WHERE session_ref=%s",
                            (future,audit_ref),
                        )
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            "DELETE FROM session_security_events WHERE session_ref=%s",(audit_ref,)
                        )

                # A used, owner-bound challenge is required to replace a registered key.
                connection.execute(
                    """
                    INSERT INTO devices (
                        id,user_id,platform,app_version,public_key_fingerprint,
                        public_key_b64,status,enrolled_at
                    ) VALUES (%s,%s,'android','1.0',%s,%s,'active',%s)
                    """,
                    (device_id,owner,"a"*64,"b2xkLWtleQ==",timestamp),
                )
                recovery_id = "recovery-code-" + owner
                connection.execute(
                    """
                    INSERT INTO webauthn_recovery_codes (id,user_id,code_hash,created_at,used_at)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (recovery_id,owner,"c"*64,timestamp,timestamp),
                )
                challenge_id = "rotation-challenge-" + owner
                connection.execute(
                    """
                    INSERT INTO device_key_rotation_challenges (
                        id,device_id,user_id,nonce_hash,previous_fingerprint,
                        proposed_public_key_b64,proposed_fingerprint,expires_at,
                        used_at,created_at,recovery_code_id
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (challenge_id,device_id,owner,"d"*64,"a"*64,
                     "bmV3LWtleQ==","e"*64,future,timestamp,timestamp,recovery_id),
                )
                connection.execute(
                    "UPDATE devices SET public_key_b64=%s,public_key_fingerprint=%s WHERE id=%s",
                    ("bmV3LWtleQ==","e"*64,device_id),
                )
                connection.execute(
                    "UPDATE device_key_rotation_challenges SET applied_at=%s WHERE id=%s",
                    (timestamp,challenge_id),
                )
                event_id = "recovery-event-" + owner
                connection.execute(
                    """
                    INSERT INTO device_security_events
                        (id,user_id,device_id,event_type,occurred_at,details_json)
                    VALUES (%s,%s,%s,'device.key_rotated',%s,%s)
                    """,
                    (event_id,owner,device_id,timestamp,'{"recovery":true}'),
                )
                notification = connection.execute(
                    "SELECT event_id,user_id,notification_type,status,payload_json "
                    "FROM security_notification_outbox WHERE event_id=%s",(event_id,)
                ).fetchone()
                assert tuple(notification[:4]) == (
                    event_id,owner,"device.recovery.completed","pending"
                )
                assert '"device_id"' in notification[4]
                with pytest.raises(psycopg.errors.CheckViolation):
                    with connection.transaction():
                        connection.execute(
                            "UPDATE security_notification_outbox SET status='unknown' WHERE event_id=%s",
                            (event_id,),
                        )
                connection.execute(
                    """
                    UPDATE security_notification_outbox
                    SET status='failed',failed_at=%s,failure_code='smtp_unavailable'
                    WHERE event_id=%s
                    """,
                    (future,event_id),
                )
                assert connection.execute(
                    "SELECT status,failed_at,failure_code FROM security_notification_outbox WHERE event_id=%s",
                    (event_id,),
                ).fetchone() == ("failed",future,"smtp_unavailable")
                raise RollbackFixture()
    except RollbackFixture:
        pass
