"""PostgreSQL-native migration runner.

This runner is intentionally separate from the SQLite Database class. The
PostgreSQL migration stream is incomplete until every SQLite migration and
security invariant has a reviewed PostgreSQL equivalent; it is not selectable
by AppState yet.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MIGRATION_LOCK_ID = 0x4149425241494E  # Stable advisory-lock namespace.


@dataclass(frozen=True)
class PostgresMigration:
    version: int
    name: str
    sql: str


MIGRATIONS: tuple[PostgresMigration, ...] = (
    PostgresMigration(
        version=1,
        name="core_identity",
        sql="""
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            created_at TEXT NOT NULL,
            deleted_at TEXT
        );
        CREATE TABLE sessions (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_sessions_user ON sessions(user_id);
        """,
    ),
    PostgresMigration(
        version=2,
        name="memory_tool_requests_and_passkey_authorization",
        sql="""
        CREATE TABLE memory_items (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            memory_type TEXT NOT NULL,
            key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence DOUBLE PRECISION NOT NULL,
            status TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE observations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            source TEXT NOT NULL,
            observation_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE adaptations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            proposal_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE audit_events (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            event_type TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE tool_requests (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            tool_id TEXT NOT NULL,
            arguments_json TEXT NOT NULL,
            status TEXT NOT NULL,
            result_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            consumed_at TEXT,
            confirmation_id TEXT,
            audit_json TEXT,
            contract_fingerprint TEXT,
            authorization_policy TEXT NOT NULL DEFAULT 'unknown'
                CHECK (authorization_policy IN ('unknown', 'read_only', 'passkey'))
        );
        CREATE INDEX idx_memory_user ON memory_items(user_id);
        CREATE INDEX idx_observation_user ON observations(user_id);
        CREATE INDEX idx_adaptation_user ON adaptations(user_id);
        CREATE INDEX idx_tool_request_user ON tool_requests(user_id);

        CREATE TABLE webauthn_credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            credential_id TEXT NOT NULL UNIQUE,
            public_key BYTEA NOT NULL,
            sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
            transports_json TEXT NOT NULL DEFAULT '[]',
            device_type TEXT,
            backed_up SMALLINT NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
            name TEXT,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT
        );
        CREATE INDEX idx_webauthn_credentials_user
            ON webauthn_credentials(user_id);

        CREATE TABLE webauthn_challenges (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            challenge_hash TEXT NOT NULL UNIQUE,
            purpose TEXT NOT NULL CHECK (
                purpose IN ('registration', 'authentication', 'tool_approval', 'recovery')
            ),
            request_id TEXT REFERENCES tool_requests(id),
            proposal_digest TEXT,
            contract_fingerprint TEXT,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_webauthn_challenges_user
            ON webauthn_challenges(user_id);
        CREATE INDEX idx_webauthn_challenges_expiry
            ON webauthn_challenges(expires_at);

        CREATE TABLE webauthn_recovery_codes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            code_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            used_at TEXT
        );
        CREATE INDEX idx_webauthn_recovery_codes_user
            ON webauthn_recovery_codes(user_id);

        CREATE TABLE tool_authorizations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            request_id TEXT NOT NULL UNIQUE REFERENCES tool_requests(id),
            challenge_id TEXT NOT NULL UNIQUE REFERENCES webauthn_challenges(id),
            credential_id TEXT NOT NULL REFERENCES webauthn_credentials(id),
            proposal_digest TEXT NOT NULL,
            contract_fingerprint TEXT NOT NULL,
            authorized_at TEXT NOT NULL
        );
        CREATE INDEX idx_tool_authorizations_user
            ON tool_authorizations(user_id);

        CREATE FUNCTION aibrain_require_active_owner()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users
                WHERE id = NEW.user_id AND deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'user account is not active'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER prevent_session_for_deleted_user
            BEFORE INSERT ON sessions
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_memory_for_deleted_user
            BEFORE INSERT ON memory_items
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_observation_for_deleted_user
            BEFORE INSERT ON observations
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_adaptation_for_deleted_user
            BEFORE INSERT ON adaptations
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_tool_request_for_deleted_user
            BEFORE INSERT ON tool_requests
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_webauthn_credential_for_deleted_user
            BEFORE INSERT ON webauthn_credentials
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_webauthn_challenge_for_deleted_user
            BEFORE INSERT ON webauthn_challenges
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_webauthn_recovery_code_for_deleted_user
            BEFORE INSERT ON webauthn_recovery_codes
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        CREATE TRIGGER prevent_tool_authorization_for_deleted_user
            BEFORE INSERT ON tool_authorizations
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();
        """,
    ),

    PostgresMigration(
        version=3,
        name="tool_execution_attempts_bindings_and_dispatch_audit",
        sql="""
        CREATE TABLE tool_execution_attempts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_id TEXT NOT NULL UNIQUE REFERENCES tool_requests(id) ON DELETE CASCADE,
            idempotency_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK (status IN (
                'claimed', 'succeeded', 'failed', 'outcome_unknown'
            )),
            claimed_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            finished_at TEXT,
            error_code TEXT,
            CHECK (
                (status = 'claimed' AND finished_at IS NULL)
                OR
                (status IN ('succeeded', 'failed', 'outcome_unknown')
                    AND finished_at IS NOT NULL)
            )
        );
        CREATE INDEX idx_tool_execution_attempts_status_claimed
            ON tool_execution_attempts(status, claimed_at);
        CREATE INDEX idx_tool_execution_attempts_user
            ON tool_execution_attempts(user_id);

        CREATE FUNCTION aibrain_validate_execution_attempt()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM tool_requests r
                JOIN users u ON u.id = r.user_id
                WHERE r.id = NEW.request_id
                  AND r.user_id = NEW.user_id
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'tool execution attempt requires an active request owner'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_tool_execution_attempt
            BEFORE INSERT ON tool_execution_attempts
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_execution_attempt();

        CREATE TABLE tool_execution_bindings (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_id TEXT NOT NULL UNIQUE REFERENCES tool_requests(id) ON DELETE CASCADE,
            idempotency_key TEXT NOT NULL UNIQUE,
            action_digest TEXT NOT NULL CHECK (length(action_digest) = 64),
            payload_json TEXT NOT NULL,
            tool_contract_fingerprint TEXT NOT NULL
                CHECK (length(tool_contract_fingerprint) = 64),
            adapter_id TEXT NOT NULL,
            adapter_version TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            provider_scope TEXT NOT NULL,
            capabilities_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_tool_execution_bindings_user
            ON tool_execution_bindings(user_id);

        CREATE FUNCTION aibrain_validate_execution_binding()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM tool_requests r
                JOIN tool_execution_attempts a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                JOIN users u ON u.id = r.user_id
                WHERE r.id = NEW.request_id
                  AND r.user_id = NEW.user_id
                  AND r.status = 'executing'
                  AND r.consumed_at IS NOT NULL
                  AND a.status = 'claimed'
                  AND a.idempotency_key = NEW.idempotency_key
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'dispatch binding requires an active claimed execution'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_tool_execution_binding
            BEFORE INSERT ON tool_execution_bindings
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_execution_binding();

        CREATE FUNCTION aibrain_reject_immutable_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_tool_execution_binding_update
            BEFORE UPDATE ON tool_execution_bindings
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();

        CREATE TABLE tool_dispatch_audit_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_id TEXT NOT NULL REFERENCES tool_requests(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL CHECK (event_type IN (
                'dispatch_started', 'dispatch_succeeded', 'dispatch_failed',
                'dispatch_unknown', 'outcome_lookup'
            )),
            action_digest TEXT NOT NULL CHECK (length(action_digest) = 64),
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_tool_dispatch_audit_user
            ON tool_dispatch_audit_events(user_id, created_at);

        CREATE FUNCTION aibrain_validate_dispatch_audit_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM tool_requests r
                JOIN tool_execution_attempts a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                JOIN users u ON u.id = r.user_id
                WHERE r.id = NEW.request_id
                  AND r.user_id = NEW.user_id
                  AND u.deleted_at IS NULL
                  AND (
                    (
                      NEW.event_type = 'dispatch_started'
                      AND r.status = 'executing'
                      AND r.consumed_at IS NOT NULL
                      AND a.status = 'claimed'
                      AND NOT EXISTS (
                        SELECT 1 FROM tool_dispatch_audit_events p
                        WHERE p.request_id = r.id AND p.user_id = r.user_id
                          AND p.event_type = 'dispatch_started'
                      )
                      AND EXISTS (
                        SELECT 1 FROM tool_execution_bindings b
                        WHERE b.request_id = r.id AND b.user_id = r.user_id
                          AND b.action_digest = NEW.action_digest
                          AND b.idempotency_key = r.id
                      )
                    )
                    OR
                    (
                      NEW.event_type IN (
                        'dispatch_succeeded', 'dispatch_failed', 'dispatch_unknown'
                      )
                      AND r.status = 'executing'
                      AND r.consumed_at IS NOT NULL
                      AND a.status = 'claimed'
                      AND NOT EXISTS (
                        SELECT 1 FROM tool_dispatch_audit_events p
                        WHERE p.request_id = r.id AND p.user_id = r.user_id
                          AND p.event_type IN (
                            'dispatch_succeeded', 'dispatch_failed', 'dispatch_unknown'
                          )
                      )
                      AND EXISTS (
                        SELECT 1 FROM tool_dispatch_audit_events s
                        WHERE s.request_id = r.id AND s.user_id = r.user_id
                          AND s.event_type = 'dispatch_started'
                          AND s.action_digest = NEW.action_digest
                      )
                    )
                    OR
                    (
                      NEW.event_type = 'outcome_lookup'
                      AND r.status = 'outcome_unknown'
                      AND a.status = 'outcome_unknown'
                      AND EXISTS (
                        SELECT 1 FROM tool_dispatch_audit_events s
                        WHERE s.request_id = r.id AND s.user_id = r.user_id
                          AND s.event_type = 'dispatch_started'
                          AND s.action_digest = NEW.action_digest
                      )
                    )
                  )
            ) THEN
                RAISE EXCEPTION 'dispatch audit event violates execution lifecycle'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_tool_dispatch_audit_event
            BEFORE INSERT ON tool_dispatch_audit_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_dispatch_audit_event();
        CREATE TRIGGER prevent_tool_dispatch_audit_update
            BEFORE UPDATE ON tool_dispatch_audit_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        """,
    ),

    PostgresMigration(
        version=4,
        name="external_adapter_certifications_and_revocations",
        sql="""
        CREATE TABLE external_adapter_certifications (
            id TEXT PRIMARY KEY,
            provider_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            adapter_version TEXT NOT NULL,
            provider_scope TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            tool_contract_fingerprint TEXT NOT NULL
                CHECK (length(tool_contract_fingerprint) = 64),
            capabilities_json TEXT NOT NULL,
            test_suite_version TEXT NOT NULL,
            conformance_results_json TEXT NOT NULL,
            test_report_sha256 TEXT NOT NULL
                CHECK (length(test_report_sha256) = 64),
            evidence_references_json TEXT NOT NULL,
            verified_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            approved_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_external_adapter_certification_lookup
            ON external_adapter_certifications(
                provider_id, adapter_id, adapter_version, provider_scope,
                tool_id, tool_contract_fingerprint, expires_at
            );
        CREATE TABLE external_adapter_certification_revocations (
            id TEXT PRIMARY KEY,
            certification_id TEXT NOT NULL
                REFERENCES external_adapter_certifications(id) ON DELETE CASCADE,
            revoked_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_external_adapter_certification_revocations
            ON external_adapter_certification_revocations(certification_id);
        CREATE FUNCTION aibrain_reject_certification_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% records are immutable', TG_TABLE_NAME
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_external_adapter_certification_update
            BEFORE UPDATE ON external_adapter_certifications
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_certification_mutation();
        CREATE TRIGGER prevent_external_adapter_certification_delete
            BEFORE DELETE ON external_adapter_certifications
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_certification_mutation();
        CREATE TRIGGER prevent_external_adapter_revocation_update
            BEFORE UPDATE ON external_adapter_certification_revocations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_certification_mutation();
        CREATE TRIGGER prevent_external_adapter_revocation_delete
            BEFORE DELETE ON external_adapter_certification_revocations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_certification_mutation();
        """,
    ),
    PostgresMigration(
        version=5,
        name="external_adapter_evidence_packages_and_artifacts",
        sql="""
        CREATE TABLE external_adapter_evidence_packages (
            id TEXT PRIMARY KEY,
            provider_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            adapter_version TEXT NOT NULL,
            provider_scope TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            tool_contract_fingerprint TEXT NOT NULL
                CHECK (length(tool_contract_fingerprint) = 64),
            capabilities_json TEXT NOT NULL,
            test_suite_version TEXT NOT NULL,
            sandbox_environment TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
            artifact_hashes_json TEXT NOT NULL,
            conformance_results_json TEXT NOT NULL,
            executed_at TEXT NOT NULL,
            verified_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'unattested'
                CHECK (provenance IN ('unattested', 'runner_attested', 'provider_signed')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE external_adapter_evidence_artifacts (
            id TEXT PRIMARY KEY,
            package_id TEXT NOT NULL
                REFERENCES external_adapter_evidence_packages(id) ON DELETE CASCADE,
            artifact_name TEXT NOT NULL,
            sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
            content BYTEA NOT NULL,
            UNIQUE(package_id, artifact_name)
        );
        CREATE INDEX idx_external_adapter_evidence_binding
            ON external_adapter_evidence_packages(
                provider_id, adapter_id, adapter_version, provider_scope,
                tool_id, tool_contract_fingerprint, expires_at
            );
        CREATE FUNCTION aibrain_reject_evidence_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% records are immutable', TG_TABLE_NAME
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_external_adapter_evidence_update
            BEFORE UPDATE ON external_adapter_evidence_packages
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_evidence_mutation();
        CREATE TRIGGER prevent_external_adapter_evidence_delete
            BEFORE DELETE ON external_adapter_evidence_packages
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_evidence_mutation();
        CREATE TRIGGER prevent_external_adapter_evidence_artifact_update
            BEFORE UPDATE ON external_adapter_evidence_artifacts
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_evidence_mutation();
        CREATE TRIGGER prevent_external_adapter_evidence_artifact_delete
            BEFORE DELETE ON external_adapter_evidence_artifacts
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_evidence_mutation();
        """,
    ),
    PostgresMigration(
        version=6,
        name="trusted_runner_keys_and_evidence_attestations",
        sql="""
        CREATE TABLE trusted_runner_keys (
            key_id TEXT PRIMARY KEY,
            runner_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            adapter_id TEXT NOT NULL,
            adapter_version TEXT NOT NULL,
            provider_scope TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            tool_contract_fingerprint TEXT NOT NULL
                CHECK (length(tool_contract_fingerprint) = 64),
            algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
            public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
            valid_from TEXT NOT NULL,
            valid_until TEXT NOT NULL,
            registered_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(public_key),
            CHECK (valid_until > valid_from)
        );
        CREATE INDEX idx_trusted_runner_keys_runner
            ON trusted_runner_keys(runner_id, valid_until);
        CREATE TABLE trusted_runner_key_revocations (
            id TEXT PRIMARY KEY,
            key_id TEXT NOT NULL REFERENCES trusted_runner_keys(key_id),
            revoked_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_trusted_runner_key_revocations
            ON trusted_runner_key_revocations(key_id);
        CREATE TABLE external_adapter_evidence_attestations (
            id TEXT PRIMARY KEY,
            package_id TEXT NOT NULL UNIQUE
                REFERENCES external_adapter_evidence_packages(id) ON DELETE CASCADE,
            key_id TEXT NOT NULL REFERENCES trusted_runner_keys(key_id),
            runner_id TEXT NOT NULL,
            nonce TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
            signature TEXT NOT NULL,
            verified_at TEXT NOT NULL
        );
        CREATE INDEX idx_evidence_attestation_key
            ON external_adapter_evidence_attestations(key_id);
        CREATE FUNCTION aibrain_reject_runner_key_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% records are immutable', TG_TABLE_NAME
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_trusted_runner_key_update
            BEFORE UPDATE ON trusted_runner_keys
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_runner_key_mutation();
        CREATE TRIGGER prevent_trusted_runner_key_delete
            BEFORE DELETE ON trusted_runner_keys
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_runner_key_mutation();
        CREATE TRIGGER prevent_runner_key_revocation_update
            BEFORE UPDATE ON trusted_runner_key_revocations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_runner_key_mutation();
        CREATE TRIGGER prevent_runner_key_revocation_delete
            BEFORE DELETE ON trusted_runner_key_revocations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_runner_key_mutation();
        CREATE TRIGGER prevent_evidence_attestation_update
            BEFORE UPDATE ON external_adapter_evidence_attestations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_runner_key_mutation();
        CREATE TRIGGER prevent_evidence_attestation_delete
            BEFORE DELETE ON external_adapter_evidence_attestations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_runner_key_mutation();
        """,
    ),
    PostgresMigration(
        version=7,
        name="security_operator_audit_events",
        sql="""
        CREATE TABLE security_operator_audit_events (
            id TEXT PRIMARY KEY,
            actor_user_id TEXT NOT NULL REFERENCES users(id),
            actor_email TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK (outcome IN ('succeeded')),
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_security_operator_audit_actor
            ON security_operator_audit_events(actor_user_id, created_at);
        CREATE INDEX idx_security_operator_audit_target
            ON security_operator_audit_events(target_type, target_id, created_at);
        CREATE FUNCTION aibrain_reject_operator_audit_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'security operator audit events are immutable'
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_security_operator_audit_update
            BEFORE UPDATE ON security_operator_audit_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_operator_audit_mutation();
        CREATE TRIGGER prevent_security_operator_audit_delete
            BEFORE DELETE ON security_operator_audit_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_operator_audit_mutation();
        """,
    ),


    PostgresMigration(
        version=8,
        name="tool_dispatch_recovery_events",
        sql="""
        CREATE TABLE tool_dispatch_recovery_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_id TEXT NOT NULL UNIQUE REFERENCES tool_requests(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL CHECK (event_type = 'dispatch_not_started'),
            action_digest TEXT NOT NULL CHECK (length(action_digest) = 64),
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_tool_dispatch_recovery_request
            ON tool_dispatch_recovery_events(request_id, created_at);
        CREATE FUNCTION aibrain_validate_dispatch_recovery_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM tool_requests r
                JOIN tool_execution_attempts a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                JOIN tool_execution_bindings b
                  ON b.request_id = r.id AND b.user_id = r.user_id
                JOIN users u ON u.id = r.user_id
                WHERE r.id = NEW.request_id
                  AND r.user_id = NEW.user_id
                  AND u.deleted_at IS NULL
                  AND r.status = 'executing'
                  AND r.consumed_at IS NOT NULL
                  AND a.status = 'claimed'
                  AND b.idempotency_key = r.id
                  AND b.action_digest = NEW.action_digest
                  AND NOT EXISTS (
                      SELECT 1 FROM tool_dispatch_audit_events s
                      WHERE s.request_id = r.id AND s.user_id = r.user_id
                        AND s.event_type = 'dispatch_started'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM tool_dispatch_recovery_events prior
                      WHERE prior.request_id = r.id AND prior.user_id = r.user_id
                  )
            ) THEN
                RAISE EXCEPTION 'dispatch recovery event violates execution lifecycle'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_tool_dispatch_recovery_event
            BEFORE INSERT ON tool_dispatch_recovery_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_dispatch_recovery_event();
        CREATE FUNCTION aibrain_reject_dispatch_recovery_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'tool dispatch recovery events are immutable'
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_tool_dispatch_recovery_update
            BEFORE UPDATE ON tool_dispatch_recovery_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_dispatch_recovery_mutation();
        """,
    ),
    PostgresMigration(
        version=9,
        name="tool_dispatch_lookup_authorizations",
        sql="""
        CREATE TABLE tool_dispatch_lookup_authorizations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_id TEXT NOT NULL REFERENCES tool_requests(id) ON DELETE CASCADE,
            certification_id TEXT NOT NULL REFERENCES external_adapter_certifications(id),
            action_digest TEXT NOT NULL CHECK (length(action_digest) = 64),
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_tool_dispatch_lookup_authorizations_request
            ON tool_dispatch_lookup_authorizations(user_id, request_id, created_at);
        CREATE FUNCTION aibrain_validate_dispatch_lookup_authorization()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM tool_requests r
                JOIN tool_execution_attempts a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                JOIN tool_execution_bindings b
                  ON b.request_id = r.id AND b.user_id = r.user_id
                JOIN tool_dispatch_audit_events s
                  ON s.request_id = r.id AND s.user_id = r.user_id
                 AND s.event_type = 'dispatch_started'
                JOIN external_adapter_certifications c
                  ON c.id = NEW.certification_id
                JOIN users u ON u.id = r.user_id
                WHERE r.id = NEW.request_id
                  AND r.user_id = NEW.user_id
                  AND u.deleted_at IS NULL
                  AND r.status = 'outcome_unknown'
                  AND r.consumed_at IS NOT NULL
                  AND a.status = 'outcome_unknown'
                  AND b.idempotency_key = r.id
                  AND b.action_digest = NEW.action_digest
                  AND s.action_digest = NEW.action_digest
                  AND c.expires_at > NEW.created_at
                  AND NOT EXISTS (
                      SELECT 1 FROM external_adapter_certification_revocations cr
                      WHERE cr.certification_id = c.id
                  )
            ) THEN
                RAISE EXCEPTION 'lookup authorization violates execution lifecycle'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_tool_dispatch_lookup_authorization
            BEFORE INSERT ON tool_dispatch_lookup_authorizations
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_dispatch_lookup_authorization();
        CREATE FUNCTION aibrain_reject_dispatch_lookup_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'tool dispatch lookup authorizations are immutable'
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_tool_dispatch_lookup_authorization_update
            BEFORE UPDATE ON tool_dispatch_lookup_authorizations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_dispatch_lookup_mutation();
        """,
    ),
    PostgresMigration(
        version=10,
        name="dispatch_audit_recovery_and_lookup_erasure_guards",
        sql="""
        CREATE FUNCTION aibrain_require_deleted_owner_for_dispatch_erasure()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users
                WHERE id = OLD.user_id AND deleted_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'dispatch history may only be deleted during account erasure'
                    USING ERRCODE = '23514';
            END IF;
            RETURN OLD;
        END;
        $$;
        CREATE TRIGGER prevent_tool_dispatch_audit_delete
            BEFORE DELETE ON tool_dispatch_audit_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_dispatch_erasure();
        CREATE TRIGGER prevent_tool_dispatch_recovery_delete
            BEFORE DELETE ON tool_dispatch_recovery_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_dispatch_erasure();
        CREATE TRIGGER prevent_tool_dispatch_lookup_authorization_delete
            BEFORE DELETE ON tool_dispatch_lookup_authorizations
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_dispatch_erasure();
        """,
    ),
    PostgresMigration(
        version=11,
        name="tool_execution_reconciliation_events",
        sql="""
        CREATE TABLE tool_execution_reconciliation_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_id TEXT NOT NULL REFERENCES tool_requests(id) ON DELETE CASCADE,
            outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
            note TEXT NOT NULL CHECK (length(btrim(note)) BETWEEN 1 AND 1000),
            error_code TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, request_id)
        );
        CREATE INDEX idx_tool_execution_reconciliation_request
            ON tool_execution_reconciliation_events(user_id, request_id, created_at);

        -- Preserve legacy reconciliation records before removing the JSON field.
        INSERT INTO tool_execution_reconciliation_events (
            id, user_id, request_id, outcome, note, error_code, created_at
        )
        SELECT
            md5(random()::text || clock_timestamp()::text || r.id),
            r.user_id,
            r.id,
            j.data -> 'execution_reconciliation' ->> 'outcome',
            j.data -> 'execution_reconciliation' ->> 'note',
            j.data -> 'execution_reconciliation' ->> 'error_code',
            COALESCE(
                j.data -> 'execution_reconciliation' ->> 'reconciled_at',
                r.updated_at
            )
        FROM tool_requests r
        JOIN users u ON u.id = r.user_id
        CROSS JOIN LATERAL (
            SELECT CASE
                WHEN pg_input_is_valid(COALESCE(r.audit_json, '{}'), 'jsonb')
                THEN COALESCE(r.audit_json, '{}')::jsonb
                ELSE '{}'::jsonb
            END AS data
        ) j
        WHERE u.deleted_at IS NULL
          AND jsonb_typeof(j.data -> 'execution_reconciliation') = 'object'
          AND j.data -> 'execution_reconciliation' ->> 'outcome'
              IN ('succeeded', 'failed')
          AND length(btrim(COALESCE(
              j.data -> 'execution_reconciliation' ->> 'note', ''
          ))) BETWEEN 1 AND 1000
        ON CONFLICT (user_id, request_id) DO NOTHING;

        UPDATE tool_requests r
        SET audit_json = (
            CASE
                WHEN pg_input_is_valid(COALESCE(r.audit_json, '{}'), 'jsonb')
                THEN COALESCE(r.audit_json, '{}')::jsonb
                ELSE '{}'::jsonb
            END #- '{execution_reconciliation}'
        )::text
        WHERE EXISTS (
            SELECT 1 FROM tool_execution_reconciliation_events e
            WHERE e.user_id = r.user_id AND e.request_id = r.id
        );

        CREATE FUNCTION aibrain_validate_execution_reconciliation_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM tool_requests r
                JOIN tool_execution_attempts a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                JOIN users u ON u.id = r.user_id
                WHERE r.id = NEW.request_id
                  AND r.user_id = NEW.user_id
                  AND u.deleted_at IS NULL
                  AND r.status = 'outcome_unknown'
                  AND r.consumed_at IS NOT NULL
                  AND a.status = 'outcome_unknown'
                  AND NOT EXISTS (
                      SELECT 1 FROM tool_execution_reconciliation_events prior
                      WHERE prior.user_id = r.user_id AND prior.request_id = r.id
                  )
            ) THEN
                RAISE EXCEPTION 'reconciliation event violates execution lifecycle'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_tool_execution_reconciliation_event
            BEFORE INSERT ON tool_execution_reconciliation_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_execution_reconciliation_event();

        CREATE FUNCTION aibrain_reject_reconciliation_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'tool execution reconciliation events are immutable'
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_tool_execution_reconciliation_update
            BEFORE UPDATE ON tool_execution_reconciliation_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_reconciliation_update();
        CREATE TRIGGER prevent_tool_execution_reconciliation_delete
            BEFORE DELETE ON tool_execution_reconciliation_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_dispatch_erasure();
        """,
    ),

    PostgresMigration(
        version=12,
        name="memory_consent_lifecycle_and_memory_binding",
        sql="""
        CREATE TABLE memory_consents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            purpose TEXT NOT NULL CHECK (purpose = 'personal_memory'),
            policy_version INTEGER NOT NULL CHECK (policy_version = 1),
            retention_days INTEGER CHECK (
                retention_days IS NULL OR retention_days BETWEEN 1 AND 3650
            ),
            granted_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE UNIQUE INDEX idx_memory_active_consent
            ON memory_consents(user_id, purpose)
            WHERE revoked_at IS NULL;
        CREATE INDEX idx_memory_consent_user_history
            ON memory_consents(user_id, granted_at);

        ALTER TABLE memory_items
            ADD COLUMN consent_id TEXT REFERENCES memory_consents(id);
        CREATE INDEX idx_memory_items_consent
            ON memory_items(user_id, consent_id, status, expires_at);

        CREATE TRIGGER prevent_memory_consent_for_deleted_user
            BEFORE INSERT ON memory_consents
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_owner();

        CREATE FUNCTION aibrain_reject_memory_consent_identity_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'memory consent identity is immutable'
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_memory_consent_identity_update
            BEFORE UPDATE OF id, user_id, purpose, policy_version, granted_at
            ON memory_consents
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_memory_consent_identity_mutation();

        CREATE FUNCTION aibrain_validate_memory_consent_revocation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
                RAISE EXCEPTION 'memory consent revocation is immutable'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER prevent_memory_consent_reactivation
            BEFORE UPDATE OF revoked_at ON memory_consents
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_memory_consent_revocation();

        CREATE FUNCTION aibrain_validate_memory_consent_retention()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.revoked_at IS NOT NULL THEN
                RAISE EXCEPTION 'revoked memory consent policy is immutable'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER prevent_memory_consent_policy_update_after_revoke
            BEFORE UPDATE OF retention_days ON memory_consents
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_memory_consent_retention();

        CREATE FUNCTION aibrain_require_deleted_owner_for_memory_consent_erasure()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users
                WHERE id = OLD.user_id AND deleted_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'memory consent history may only be deleted during account erasure'
                    USING ERRCODE = '23514';
            END IF;
            RETURN OLD;
        END;
        $$;
        CREATE TRIGGER prevent_memory_consent_delete
            BEFORE DELETE ON memory_consents
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_memory_consent_erasure();

        CREATE FUNCTION aibrain_validate_memory_item_consent()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM memory_consents c
                JOIN users u ON u.id = c.user_id
                WHERE c.id = NEW.consent_id
                  AND c.user_id = NEW.user_id
                  AND c.purpose = 'personal_memory'
                  AND c.revoked_at IS NULL
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'memory creation or update requires active owner consent'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_memory_consent_insert
            BEFORE INSERT ON memory_items
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_memory_item_consent();
        CREATE TRIGGER validate_memory_consent_update
            BEFORE UPDATE ON memory_items
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_memory_item_consent();
        """,
    ),
    PostgresMigration(
        version=13,
        name="learning_adaptation_events_and_evaluations",
        sql="""
        ALTER TABLE adaptations ADD COLUMN expires_at TEXT;

        CREATE TABLE learning_adaptation_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            adaptation_id TEXT NOT NULL REFERENCES adaptations(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL CHECK (event_type IN (
                'proposed', 'approved', 'rejected', 'suspended',
                'revoked', 'expired', 'evaluated'
            )),
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_learning_adaptation_events_owner
            ON learning_adaptation_events(user_id, adaptation_id, created_at);

        CREATE TABLE learning_evaluations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            adaptation_id TEXT NOT NULL REFERENCES adaptations(id) ON DELETE CASCADE,
            outcome TEXT NOT NULL CHECK (
                outcome IN ('improved', 'no_change', 'regressed', 'inconclusive')
            ),
            metric TEXT NOT NULL CHECK (length(btrim(metric)) BETWEEN 1 AND 120),
            baseline_value DOUBLE PRECISION NOT NULL,
            observed_value DOUBLE PRECISION NOT NULL,
            confidence DOUBLE PRECISION NOT NULL CHECK (
                confidence >= 0.0 AND confidence <= 1.0
            ),
            evidence_json TEXT NOT NULL,
            source TEXT NOT NULL CHECK (source = 'user_reported'),
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_learning_evaluations_owner
            ON learning_evaluations(user_id, adaptation_id, created_at);

        CREATE FUNCTION aibrain_reject_learning_history_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '% records are immutable', TG_TABLE_NAME
                USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_learning_adaptation_event_update
            BEFORE UPDATE ON learning_adaptation_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_learning_history_mutation();
        CREATE TRIGGER prevent_learning_evaluation_update
            BEFORE UPDATE ON learning_evaluations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_learning_history_mutation();

        CREATE FUNCTION aibrain_require_deleted_owner_for_learning_erasure()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users
                WHERE id = OLD.user_id AND deleted_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'learning history may only be deleted during account erasure'
                    USING ERRCODE = '23514';
            END IF;
            RETURN OLD;
        END;
        $$;
        CREATE TRIGGER prevent_learning_adaptation_event_delete
            BEFORE DELETE ON learning_adaptation_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_learning_erasure();
        CREATE TRIGGER prevent_learning_evaluation_delete
            BEFORE DELETE ON learning_evaluations
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_learning_erasure();

        CREATE FUNCTION aibrain_validate_learning_adaptation_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT (
                OLD.status = NEW.status
                OR (OLD.status = 'pending' AND NEW.status IN (
                    'approved', 'rejected', 'expired'
                ))
                OR (OLD.status = 'approved' AND NEW.status IN (
                    'suspended', 'revoked', 'expired'
                ))
                OR (OLD.status = 'suspended' AND NEW.status IN (
                    'approved', 'revoked', 'expired'
                ))
            ) THEN
                RAISE EXCEPTION 'invalid learning adaptation transition'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_learning_adaptation_transition
            BEFORE UPDATE OF status ON adaptations
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_learning_adaptation_transition();

        CREATE FUNCTION aibrain_validate_learning_adaptation_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM adaptations a
                JOIN users u ON u.id = a.user_id
                WHERE a.id = NEW.adaptation_id
                  AND a.user_id = NEW.user_id
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'learning event owner mismatch'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_learning_adaptation_event
            BEFORE INSERT ON learning_adaptation_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_learning_adaptation_event();

        CREATE FUNCTION aibrain_validate_learning_evaluation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM adaptations a
                JOIN users u ON u.id = a.user_id
                WHERE a.id = NEW.adaptation_id
                  AND a.user_id = NEW.user_id
                  AND a.status = 'approved'
                  AND (a.expires_at IS NULL OR a.expires_at > NEW.created_at)
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'evaluation requires an approved owner adaptation'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_learning_evaluation
            BEFORE INSERT ON learning_evaluations
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_learning_evaluation();
        """,
    ),

    PostgresMigration(
        version=14,
        name="agent_identity_and_registration_events",
        sql="""
        CREATE FUNCTION aibrain_require_deleted_owner_for_agent_erasure()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'agent records may only be deleted during account erasure'
                    USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END;
        $$;

        CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
            description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
            metadata_json TEXT NOT NULL DEFAULT '{}'
                CHECK (metadata_json::jsonb IS NOT NULL),
            status TEXT NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft', 'active', 'suspended', 'terminated')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX idx_agents_owner_created ON agents(user_id, created_at, id);
        CREATE TABLE agent_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            actor_user_id TEXT NOT NULL REFERENCES users(id),
            event_type TEXT NOT NULL CHECK (event_type IN ('registered')),
            details_json TEXT NOT NULL CHECK (details_json::jsonb IS NOT NULL),
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_agent_events_owner_agent
            ON agent_events(user_id, agent_id, created_at, id);
        CREATE FUNCTION aibrain_validate_agent_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users WHERE id = NEW.user_id AND deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'agent owner account is not active'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_insert BEFORE INSERT ON agents
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_insert();
        CREATE FUNCTION aibrain_reject_agent_identity_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'agent identity is immutable' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER prevent_agent_identity_update BEFORE UPDATE ON agents
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_agent_identity_update();
        CREATE FUNCTION aibrain_validate_agent_event_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.actor_user_id <> NEW.user_id OR NOT EXISTS (
                SELECT 1 FROM agents a JOIN users u ON u.id = a.user_id
                WHERE a.id = NEW.agent_id AND a.user_id = NEW.user_id
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'agent event owner mismatch' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_event_insert BEFORE INSERT ON agent_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_event_insert();
        CREATE FUNCTION aibrain_reject_agent_event_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'agent events are immutable' USING ERRCODE = '23514';
        END;
        $$;
        CREATE TRIGGER prevent_agent_event_update BEFORE UPDATE ON agent_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_agent_event_mutation();
        CREATE TRIGGER prevent_agent_event_delete BEFORE DELETE ON agent_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        """,
    ),
    PostgresMigration(
        version=15,
        name="agent_lifecycle_event_guards",
        sql="""
        CREATE OR REPLACE FUNCTION aibrain_validate_agent_event_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            current_status TEXT;
            initial_status TEXT;
            from_status TEXT;
            to_status TEXT;
            event_valid BOOLEAN := FALSE;
        BEGIN
            SELECT status INTO current_status FROM agents
            WHERE id = NEW.agent_id AND user_id = NEW.user_id;
            IF NEW.actor_user_id <> NEW.user_id OR current_status IS NULL
               OR NOT EXISTS (SELECT 1 FROM users
                              WHERE id = NEW.user_id AND deleted_at IS NULL) THEN
                RAISE EXCEPTION 'agent event owner mismatch'
                    USING ERRCODE = '23514';
            END IF;
            initial_status := NEW.details_json::jsonb ->> 'initial_status';
            from_status := NEW.details_json::jsonb ->> 'from_status';
            to_status := NEW.details_json::jsonb ->> 'to_status';
            event_valid := CASE NEW.event_type
                WHEN 'registered' THEN current_status = 'draft'
                    AND initial_status = 'draft'
                    AND NOT EXISTS (SELECT 1 FROM agent_events WHERE agent_id = NEW.agent_id)
                WHEN 'activated' THEN current_status = 'draft'
                    AND from_status = 'draft' AND to_status = 'active'
                WHEN 'suspended' THEN current_status = 'active'
                    AND from_status = 'active' AND to_status = 'suspended'
                WHEN 'resumed' THEN current_status = 'suspended'
                    AND from_status = 'suspended' AND to_status = 'active'
                WHEN 'terminated' THEN current_status IN ('draft','active','suspended')
                    AND from_status = current_status AND to_status = 'terminated'
                ELSE FALSE
            END;
            IF NOT event_valid THEN
                RAISE EXCEPTION 'agent event owner or transition mismatch'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        ALTER TABLE agent_events DROP CONSTRAINT IF EXISTS agent_events_event_type_check;
        ALTER TABLE agent_events ADD CONSTRAINT agent_events_event_type_check
            CHECK (event_type IN ('registered','activated','suspended','resumed','terminated'));
        CREATE FUNCTION aibrain_validate_agent_status_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.status IS DISTINCT FROM OLD.status THEN
                IF OLD.status = 'terminated' OR NOT EXISTS (
                    SELECT 1 FROM agent_events e
                    WHERE e.agent_id = OLD.id AND e.user_id = OLD.user_id
                      AND e.details_json::jsonb ->> 'from_status' = OLD.status
                      AND e.details_json::jsonb ->> 'to_status' = NEW.status
                      AND ( (e.event_type='activated' AND OLD.status='draft' AND NEW.status='active')
                         OR (e.event_type='suspended' AND OLD.status='active' AND NEW.status='suspended')
                         OR (e.event_type='resumed' AND OLD.status='suspended' AND NEW.status='active')
                         OR (e.event_type='terminated' AND OLD.status IN ('draft','active','suspended')
                             AND NEW.status='terminated') )
                ) THEN
                    RAISE EXCEPTION 'agent status change requires a matching lifecycle event'
                        USING ERRCODE = '23514';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_status_transition BEFORE UPDATE OF status ON agents
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_status_transition();
        """,
    ),
    PostgresMigration(
        version=16,
        name="agent_capability_grants_tasks_messages_and_controls",
        sql="""
        CREATE TABLE agent_capability_grants (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            capability TEXT NOT NULL CHECK (capability IN (
                'research.read','notes.read','notes.write','calendar.read',
                'calendar.write','web.search','files.read'
            )),
            expires_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_agent_grants_owner_agent
            ON agent_capability_grants(user_id, agent_id, created_at);
        CREATE TABLE agent_capability_revocations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            grant_id TEXT NOT NULL UNIQUE
                REFERENCES agent_capability_grants(id) ON DELETE CASCADE,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE agent_tasks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            title TEXT NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 160),
            goal TEXT NOT NULL CHECK (length(goal) <= 4000),
            context_json TEXT NOT NULL CHECK (context_json::jsonb IS NOT NULL),
            capability_ceiling_json TEXT NOT NULL
                CHECK (jsonb_typeof(capability_ceiling_json::jsonb) = 'array'),
            status TEXT NOT NULL CHECK (status IN
                ('assigned','in_progress','completed','failed','cancelled','expired')),
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX idx_agent_tasks_owner_agent
            ON agent_tasks(user_id, agent_id, status, expires_at);
        CREATE TABLE agent_task_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
            actor_user_id TEXT NOT NULL REFERENCES users(id),
            event_type TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (details_json::jsonb IS NOT NULL),
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_agent_task_events_owner_task
            ON agent_task_events(user_id, task_id, created_at, id);
        CREATE TABLE agent_messages (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            sender_agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            recipient_agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            task_id TEXT REFERENCES agent_tasks(id) ON DELETE CASCADE,
            payload_json TEXT NOT NULL CHECK (payload_json::jsonb IS NOT NULL),
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_agent_messages_owner_recipient
            ON agent_messages(user_id, recipient_agent_id, created_at, id);
        CREATE TABLE agent_control_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (details_json::jsonb IS NOT NULL),
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_agent_control_events_owner_agent
            ON agent_control_events(user_id, agent_id, created_at, id);

        CREATE OR REPLACE FUNCTION aibrain_require_deleted_owner_for_agent_erasure()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'agent records may only be deleted during account erasure'
                    USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END;
        $$;
        CREATE TRIGGER prevent_agent_delete BEFORE DELETE ON agents
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();

        CREATE FUNCTION aibrain_validate_agent_grant()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agents a JOIN users u ON u.id=a.user_id
                WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                  AND a.status='active' AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'grant requires active owned agent' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_grant_insert BEFORE INSERT ON agent_capability_grants
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_grant();
        CREATE TRIGGER prevent_agent_grant_update BEFORE UPDATE ON agent_capability_grants
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_agent_grant_delete BEFORE DELETE ON agent_capability_grants
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        CREATE FUNCTION aibrain_validate_agent_revocation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agent_capability_grants g
                JOIN users u ON u.id=g.user_id
                WHERE g.id=NEW.grant_id AND g.user_id=NEW.user_id
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'grant revocation owner mismatch' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_revocation_insert BEFORE INSERT ON agent_capability_revocations
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_revocation();
        CREATE TRIGGER prevent_agent_revocation_update BEFORE UPDATE ON agent_capability_revocations
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_agent_revocation_delete BEFORE DELETE ON agent_capability_revocations
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();

        CREATE FUNCTION aibrain_validate_agent_task_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE item JSONB;
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agents a JOIN users u ON u.id=a.user_id
                WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                  AND a.status='active' AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'task requires active owned agent'
                    USING ERRCODE='23514';
            END IF;
            FOR item IN SELECT value FROM jsonb_array_elements(NEW.capability_ceiling_json::jsonb)
            LOOP
                IF jsonb_typeof(item) <> 'string' OR NOT EXISTS (
                    SELECT 1 FROM agent_capability_grants g
                    WHERE g.user_id=NEW.user_id AND g.agent_id=NEW.agent_id
                      AND g.capability=item #>> '{}'
                      AND (g.expires_at IS NULL OR g.expires_at > NEW.created_at)
                      AND NOT EXISTS (SELECT 1 FROM agent_capability_revocations r
                                      WHERE r.grant_id=g.id)
                ) THEN
                    RAISE EXCEPTION 'task capability ceiling exceeds active grants'
                        USING ERRCODE='23514';
                END IF;
            END LOOP;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_task_insert BEFORE INSERT ON agent_tasks
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_task_insert();
        CREATE FUNCTION aibrain_reject_agent_task_identity_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'task identity is immutable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER prevent_agent_task_identity_update BEFORE UPDATE ON agent_tasks
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_agent_task_identity_update();
        CREATE TRIGGER prevent_agent_task_delete BEFORE DELETE ON agent_tasks
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        CREATE TRIGGER prevent_agent_task_update BEFORE UPDATE ON agent_tasks
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE FUNCTION aibrain_validate_agent_task_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.actor_user_id <> NEW.user_id OR NOT EXISTS (
                SELECT 1 FROM agent_tasks t JOIN users u ON u.id=t.user_id
                WHERE t.id=NEW.task_id AND t.user_id=NEW.user_id
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'task event owner mismatch' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_task_event_insert BEFORE INSERT ON agent_task_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_task_event();
        CREATE TRIGGER prevent_agent_task_event_update BEFORE UPDATE ON agent_task_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_agent_task_event_delete BEFORE DELETE ON agent_task_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        CREATE FUNCTION aibrain_validate_agent_task_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.status IS DISTINCT FROM OLD.status AND NOT EXISTS (
                SELECT 1 FROM agent_task_events e
                WHERE e.task_id=OLD.id AND e.user_id=OLD.user_id
                  AND e.details_json::jsonb ->> 'from_status'=OLD.status
                  AND e.details_json::jsonb ->> 'to_status'=NEW.status
            ) THEN
                RAISE EXCEPTION 'task status change requires matching event'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_task_transition BEFORE UPDATE OF status ON agent_tasks
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_task_transition();

        CREATE FUNCTION aibrain_validate_agent_message()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agents s JOIN agents r ON r.id=NEW.recipient_agent_id
                JOIN users u ON u.id=s.user_id
                WHERE s.id=NEW.sender_agent_id AND s.user_id=NEW.user_id
                  AND r.user_id=NEW.user_id AND s.status='active'
                  AND r.status='active' AND u.deleted_at IS NULL
            ) OR (NEW.task_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM agent_tasks t WHERE t.id=NEW.task_id
                  AND t.user_id=NEW.user_id AND t.agent_id=NEW.recipient_agent_id
            )) THEN
                RAISE EXCEPTION 'message requires same-owner active agents and matching task'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_message_insert BEFORE INSERT ON agent_messages
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_message();
        CREATE TRIGGER prevent_agent_message_update BEFORE UPDATE ON agent_messages
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_agent_message_delete BEFORE DELETE ON agent_messages
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();

        CREATE FUNCTION aibrain_validate_agent_control_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agents a JOIN users u ON u.id=a.user_id
                WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'agent control event owner mismatch' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_control_event_insert BEFORE INSERT ON agent_control_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_control_event();
        CREATE TRIGGER prevent_agent_control_event_update BEFORE UPDATE ON agent_control_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_agent_control_event_delete BEFORE DELETE ON agent_control_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        """,
    ),
    PostgresMigration(
        version=17,
        name="agent_task_transition_and_definition_guards",
        sql="""
        CREATE OR REPLACE FUNCTION aibrain_validate_agent_task_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE current_status TEXT;
            from_status TEXT;
            to_status TEXT;
        BEGIN
            SELECT status INTO current_status FROM agent_tasks
            WHERE id=NEW.task_id AND user_id=NEW.user_id;
            from_status := NEW.details_json::jsonb ->> 'from_status';
            to_status := NEW.details_json::jsonb ->> 'to_status';
            IF NEW.actor_user_id <> NEW.user_id OR current_status IS NULL
               OR NOT EXISTS (SELECT 1 FROM users WHERE id=NEW.user_id AND deleted_at IS NULL)
               OR NOT (
                    (NEW.event_type='assigned' AND current_status='assigned'
                     AND from_status IS NULL AND to_status='assigned')
                    OR (from_status=current_status AND to_status=NEW.event_type
                        AND ((current_status='assigned' AND NEW.event_type IN
                              ('in_progress','completed','failed','cancelled','expired'))
                          OR (current_status='in_progress' AND NEW.event_type IN
                              ('completed','failed','cancelled','expired'))))
               ) THEN
                RAISE EXCEPTION 'task event transition mismatch' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE FUNCTION aibrain_reject_agent_task_definition_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.title IS DISTINCT FROM OLD.title OR NEW.goal IS DISTINCT FROM OLD.goal
               OR NEW.context_json IS DISTINCT FROM OLD.context_json
               OR NEW.capability_ceiling_json IS DISTINCT FROM OLD.capability_ceiling_json
               OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
               OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
               OR NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'task definition is immutable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        DROP TRIGGER prevent_agent_task_update ON agent_tasks;
        CREATE TRIGGER prevent_agent_task_content_update BEFORE UPDATE ON agent_tasks
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_agent_task_definition_update();
        """,
    ),
    PostgresMigration(
        version=18,
        name="agent_runs_steps_and_event_history",
        sql="""
        CREATE TABLE agent_runs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
            actions_json TEXT NOT NULL CHECK (actions_json::jsonb IS NOT NULL),
            plan_digest TEXT NOT NULL CHECK (length(plan_digest)=64),
            status TEXT NOT NULL CHECK (status IN
                ('proposed','authorized','running','completed','failed','cancelled','expired')),
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            authorized_at TEXT,
            started_at TEXT,
            finished_at TEXT
        );
        CREATE INDEX idx_agent_runs_owner_task ON agent_runs(user_id,task_id,created_at,id);
        CREATE INDEX idx_agent_runs_status_expiry ON agent_runs(status,expires_at);
        CREATE TABLE agent_run_steps (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 9),
            tool_id TEXT NOT NULL,
            arguments_json TEXT NOT NULL CHECK (arguments_json::jsonb IS NOT NULL),
            contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint)=64),
            required_capability TEXT,
            status TEXT NOT NULL CHECK (status IN ('pending','running','completed','failed','skipped')),
            tool_request_id TEXT,
            result_json TEXT CHECK (result_json IS NULL OR result_json::jsonb IS NOT NULL),
            error_code TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(run_id,ordinal)
        );
        CREATE INDEX idx_agent_run_steps_owner_run ON agent_run_steps(user_id,run_id,ordinal);
        CREATE TABLE agent_run_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
            actor_user_id TEXT NOT NULL REFERENCES users(id),
            event_type TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (jsonb_typeof(details_json::jsonb)='object'),
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_agent_run_events_owner_run
            ON agent_run_events(user_id,run_id,created_at,id);
        CREATE FUNCTION aibrain_validate_agent_run_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agents a
                JOIN agent_tasks t ON t.agent_id=a.id AND t.user_id=a.user_id
                JOIN users u ON u.id=a.user_id
                WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                  AND a.status='active' AND u.deleted_at IS NULL
                  AND t.id=NEW.task_id AND t.user_id=NEW.user_id
                  AND t.status IN ('assigned','in_progress')
                  AND t.expires_at > NEW.created_at
            ) THEN
                RAISE EXCEPTION 'agent run requires active owned agent and live task'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_run_insert BEFORE INSERT ON agent_runs
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_insert();
        CREATE FUNCTION aibrain_reject_agent_run_definition_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.agent_id IS DISTINCT FROM OLD.agent_id OR NEW.task_id IS DISTINCT FROM OLD.task_id
               OR NEW.actions_json IS DISTINCT FROM OLD.actions_json
               OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
               OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'agent run definition is immutable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER prevent_agent_run_definition_update BEFORE UPDATE ON agent_runs
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_agent_run_definition_update();
        CREATE TRIGGER prevent_agent_run_delete BEFORE DELETE ON agent_runs
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        CREATE FUNCTION aibrain_validate_agent_run_event()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.actor_user_id <> NEW.user_id OR NOT EXISTS (
                SELECT 1 FROM agent_runs r JOIN users u ON u.id=r.user_id
                WHERE r.id=NEW.run_id AND r.user_id=NEW.user_id AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'agent run event owner mismatch' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_run_event_insert BEFORE INSERT ON agent_run_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_event();
        CREATE TRIGGER prevent_agent_run_event_update BEFORE UPDATE ON agent_run_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_agent_run_event_delete BEFORE DELETE ON agent_run_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        CREATE FUNCTION aibrain_validate_agent_run_status_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.status IS DISTINCT FROM OLD.status AND NOT EXISTS (
                SELECT 1 FROM agent_run_events e
                WHERE e.run_id=OLD.id AND e.user_id=OLD.user_id
                  AND e.details_json::jsonb ->> 'from_status'=OLD.status
                  AND e.details_json::jsonb ->> 'to_status'=NEW.status
            ) THEN
                RAISE EXCEPTION 'agent run status change requires matching event'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_run_status_transition BEFORE UPDATE OF status ON agent_runs
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_status_transition();
        CREATE FUNCTION aibrain_validate_agent_run_step_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agent_runs r JOIN users u ON u.id=r.user_id
                WHERE r.id=NEW.run_id AND r.user_id=NEW.user_id AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'agent run step owner mismatch' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_run_step_insert BEFORE INSERT ON agent_run_steps
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_step_insert();
        CREATE FUNCTION aibrain_reject_agent_run_step_definition_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.run_id IS DISTINCT FROM OLD.run_id OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
               OR NEW.tool_id IS DISTINCT FROM OLD.tool_id
               OR NEW.arguments_json IS DISTINCT FROM OLD.arguments_json
               OR NEW.contract_fingerprint IS DISTINCT FROM OLD.contract_fingerprint
               OR NEW.required_capability IS DISTINCT FROM OLD.required_capability
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'agent run step definition is immutable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER prevent_agent_run_step_definition_update BEFORE UPDATE ON agent_run_steps
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_agent_run_step_definition_update();
        CREATE TRIGGER prevent_agent_run_step_delete BEFORE DELETE ON agent_run_steps
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        CREATE FUNCTION aibrain_validate_agent_run_step_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.status IS DISTINCT FROM OLD.status AND NOT EXISTS (
                SELECT 1 FROM agent_run_events e
                WHERE e.run_id=OLD.run_id AND e.user_id=OLD.user_id
                  AND e.details_json::jsonb ->> 'step_id'=OLD.id
                  AND ((OLD.status='pending' AND
                       ((NEW.status='running' AND e.event_type='step_started')
                        OR (NEW.status='failed' AND e.event_type='step_failed')
                        OR (NEW.status='skipped' AND e.event_type='step_skipped')))
                    OR (OLD.status='running' AND
                       ((NEW.status='completed' AND e.event_type='step_completed')
                        OR (NEW.status='failed' AND e.event_type='step_failed')))
                  )
            ) THEN
                RAISE EXCEPTION 'agent run step status change requires matching event'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER validate_agent_run_step_status_transition
            BEFORE UPDATE OF status ON agent_run_steps
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_step_transition();
        """,
    ),

    PostgresMigration(
        version=19,
        name="integration_connections_grants_and_events",
        sql="""
        CREATE TABLE integration_connections (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            integration_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN
                ('pending_verification','active','revoked','expired','disconnected')),
            consent_version TEXT NOT NULL,
            consented_at TEXT NOT NULL,
            verified_at TEXT,
            expires_at TEXT,
            secret_ref TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(id,user_id)
        );
        CREATE INDEX idx_integration_connections_owner
            ON integration_connections(user_id,status,created_at);
        CREATE TABLE integration_connection_grants (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            connection_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending','active','revoked','expired')),
            expires_at TEXT,
            revoked_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(connection_id,user_id)
                REFERENCES integration_connections(id,user_id) ON DELETE CASCADE,
            UNIQUE(connection_id,scope)
        );
        CREATE INDEX idx_integration_grants_owner
            ON integration_connection_grants(user_id,connection_id,status,scope);
        CREATE TABLE integration_connection_events (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            connection_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (jsonb_typeof(details_json::jsonb)='object'),
            created_at TEXT NOT NULL,
            FOREIGN KEY(connection_id,user_id)
                REFERENCES integration_connections(id,user_id) ON DELETE CASCADE
        );
        CREATE INDEX idx_integration_connection_events_owner
            ON integration_connection_events(user_id,connection_id,created_at,id);
        CREATE FUNCTION aibrain_validate_integration_connection_insert()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users u WHERE u.id=NEW.user_id AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'integration connection requires active owner'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER validate_integration_connection_insert
            BEFORE INSERT ON integration_connections
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_integration_connection_insert();
        CREATE FUNCTION aibrain_require_verified_integration_activation()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.status='active' AND
               (NEW.verified_at IS NULL OR NEW.secret_ref IS NULL
                OR length(btrim(NEW.secret_ref))=0) THEN
                RAISE EXCEPTION 'integration activation requires trusted verification and secret reference'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER require_verified_integration_activation
            BEFORE UPDATE OF status ON integration_connections
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_verified_integration_activation();
        CREATE FUNCTION aibrain_validate_integration_grant_insert()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM integration_connections c
                JOIN users u ON u.id=c.user_id
                WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'integration grant owner mismatch' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER validate_integration_grant_insert
            BEFORE INSERT ON integration_connection_grants
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_integration_grant_insert();
        CREATE FUNCTION aibrain_require_active_connection_for_active_grant()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.status='active' AND NOT EXISTS (
                SELECT 1 FROM integration_connections c
                WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                  AND c.status='active'
            ) THEN
                RAISE EXCEPTION 'active integration grant requires active connection'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER require_active_connection_for_active_grant
            BEFORE UPDATE OF status ON integration_connection_grants
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_active_connection_for_active_grant();
        CREATE FUNCTION aibrain_reject_integration_grant_scope_update()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
               OR NEW.scope IS DISTINCT FROM OLD.scope
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'integration grant definition is immutable'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER prevent_integration_grant_scope_update
            BEFORE UPDATE ON integration_connection_grants
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_integration_grant_scope_update();
        CREATE FUNCTION aibrain_validate_integration_connection_event_insert()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM integration_connections c
                JOIN users u ON u.id=c.user_id
                WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                  AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'integration connection event owner mismatch'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER validate_integration_connection_event_insert
            BEFORE INSERT ON integration_connection_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_integration_connection_event_insert();
        CREATE TRIGGER prevent_integration_connection_event_update
            BEFORE UPDATE ON integration_connection_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_integration_connection_event_delete
            BEFORE DELETE ON integration_connection_events
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        """,
    ),
    PostgresMigration(
        version=20,
        name="integration_secret_vault_and_terminal_erasure",
        sql="""
        CREATE TABLE integration_secrets (
            secret_ref TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            nonce BYTEA NOT NULL CHECK (octet_length(nonce)=12),
            ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext)>=16),
            key_version INTEGER NOT NULL CHECK (key_version>=1),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(connection_id,user_id)
                REFERENCES integration_connections(id,user_id) ON DELETE CASCADE,
            UNIQUE(connection_id)
        );
        CREATE INDEX idx_integration_secrets_owner
            ON integration_secrets(user_id,connection_id);
        CREATE OR REPLACE FUNCTION aibrain_require_verified_integration_activation()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.status='active' AND (
                NEW.verified_at IS NULL OR NEW.secret_ref IS NULL
                OR NOT EXISTS (
                    SELECT 1 FROM integration_secrets s
                    WHERE s.secret_ref=NEW.secret_ref
                      AND s.user_id=NEW.user_id
                      AND s.connection_id=NEW.id
                      AND s.integration_id=NEW.integration_id
                )
            ) THEN
                RAISE EXCEPTION 'integration activation requires verified vault credentials'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE OR REPLACE FUNCTION aibrain_validate_integration_secret_insert()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM integration_connections c
                JOIN users u ON u.id=c.user_id
                WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                  AND c.integration_id=NEW.integration_id
                  AND c.status='pending_verification' AND u.deleted_at IS NULL
            ) THEN
                RAISE EXCEPTION 'vault secret requires matching pending owner connection'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER validate_integration_secret_insert
            BEFORE INSERT ON integration_secrets
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_integration_secret_insert();
        CREATE FUNCTION aibrain_reject_integration_secret_identity_update()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.secret_ref IS DISTINCT FROM OLD.secret_ref
               OR NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
               OR NEW.integration_id IS DISTINCT FROM OLD.integration_id
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'vault secret identity is immutable'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER prevent_integration_secret_identity_update
            BEFORE UPDATE ON integration_secrets
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_integration_secret_identity_update();
        CREATE FUNCTION aibrain_validate_integration_secret_delete()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL
            ) AND NOT EXISTS (
                SELECT 1 FROM integration_connections c
                WHERE c.id=OLD.connection_id AND c.user_id=OLD.user_id
                  AND c.status IN ('revoked','disconnected','expired')
            ) THEN
                RAISE EXCEPTION 'vault secrets may only be deleted during revocation or account erasure'
                    USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END;
        $;
        CREATE TRIGGER prevent_integration_secret_delete
            BEFORE DELETE ON integration_secrets
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_integration_secret_delete();
        CREATE FUNCTION aibrain_erase_integration_secret_on_terminal_connection()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.status IN ('revoked','disconnected','expired')
               AND OLD.status IS DISTINCT FROM NEW.status THEN
                DELETE FROM integration_secrets
                WHERE connection_id=NEW.id AND user_id=NEW.user_id;
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER erase_integration_secret_on_terminal_connection
            AFTER UPDATE OF status ON integration_connections
            FOR EACH ROW EXECUTE FUNCTION aibrain_erase_integration_secret_on_terminal_connection();
        """,
    ),
    PostgresMigration(
        version=21,
        name="agent_run_integration_bindings",
        sql="""
        CREATE TABLE agent_run_integration_bindings (
            step_id TEXT PRIMARY KEY REFERENCES agent_run_steps(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            manifest_version TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint)=64),
            required_scopes_json TEXT NOT NULL
                CHECK (jsonb_typeof(required_scopes_json::jsonb)='array'),
            created_at TEXT NOT NULL,
            FOREIGN KEY(connection_id,user_id)
                REFERENCES integration_connections(id,user_id) ON DELETE CASCADE
        );
        CREATE INDEX idx_agent_run_integration_bindings_owner
            ON agent_run_integration_bindings(user_id,run_id,step_id);
        CREATE FUNCTION aibrain_validate_agent_run_integration_binding()
        RETURNS trigger LANGUAGE plpgsql AS $
        DECLARE requested_scope TEXT;
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM agent_run_steps s
                JOIN agent_runs r ON r.id=s.run_id AND r.user_id=s.user_id
                JOIN integration_connections c
                  ON c.id=NEW.connection_id AND c.user_id=NEW.user_id
                JOIN users u ON u.id=NEW.user_id
                WHERE s.id=NEW.step_id AND s.user_id=NEW.user_id
                  AND s.run_id=NEW.run_id AND r.status='proposed'
                  AND s.status='pending' AND u.deleted_at IS NULL
                  AND c.integration_id=NEW.integration_id AND c.status='active'
                  AND (c.expires_at IS NULL OR c.expires_at>NEW.created_at)
                  AND s.tool_id=NEW.tool_id
                  AND s.contract_fingerprint=NEW.contract_fingerprint
            ) THEN
                RAISE EXCEPTION 'integration binding requires matching proposed run, step, and active owner connection'
                    USING ERRCODE='23514';
            END IF;
            IF jsonb_typeof(NEW.required_scopes_json::jsonb) <> 'array'
               OR jsonb_array_length(NEW.required_scopes_json::jsonb)=0 THEN
                RAISE EXCEPTION 'integration binding requires exact active owner-granted scopes'
                    USING ERRCODE='23514';
            END IF;
            FOR requested_scope IN
                SELECT jsonb_array_elements_text(NEW.required_scopes_json::jsonb)
            LOOP
                IF NOT EXISTS (
                    SELECT 1 FROM integration_connection_grants g
                    WHERE g.user_id=NEW.user_id AND g.connection_id=NEW.connection_id
                      AND g.scope=requested_scope AND g.status='active'
                      AND g.revoked_at IS NULL
                      AND (g.expires_at IS NULL OR g.expires_at>NEW.created_at)
                ) THEN
                    RAISE EXCEPTION 'integration binding requires exact active owner-granted scopes'
                        USING ERRCODE='23514';
                END IF;
            END LOOP;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER validate_agent_run_integration_binding_insert
            BEFORE INSERT ON agent_run_integration_bindings
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_integration_binding();
        CREATE TRIGGER prevent_agent_run_integration_binding_update
            BEFORE UPDATE ON agent_run_integration_bindings
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_immutable_update();
        CREATE TRIGGER prevent_agent_run_integration_binding_delete
            BEFORE DELETE ON agent_run_integration_bindings
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        """,
    ),
    PostgresMigration(
        version=22,
        name="agent_run_integration_dispatch_lifecycle",
        sql="""
        CREATE TABLE agent_run_integration_dispatches (
            step_id TEXT PRIMARY KEY REFERENCES agent_run_steps(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            integration_id TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint)=64),
            status TEXT NOT NULL CHECK (status IN
                ('prepared','dispatch_started','succeeded','failed','outcome_unknown')),
            dispatch_started_at TEXT,
            finished_at TEXT,
            outcome_json TEXT CHECK (outcome_json IS NULL OR jsonb_typeof(outcome_json::jsonb) IS NOT NULL),
            error_code TEXT CHECK (error_code IS NULL OR
                (length(error_code) BETWEEN 1 AND 64 AND error_code !~ '[^A-Z0-9_]')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(connection_id,user_id)
                REFERENCES integration_connections(id,user_id) ON DELETE CASCADE,
            CHECK (
                (status='prepared' AND dispatch_started_at IS NULL
                    AND finished_at IS NULL AND outcome_json IS NULL AND error_code IS NULL)
                OR
                (status='dispatch_started' AND dispatch_started_at IS NOT NULL
                    AND finished_at IS NULL AND outcome_json IS NULL AND error_code IS NULL)
                OR
                (status='succeeded' AND dispatch_started_at IS NOT NULL
                    AND finished_at IS NOT NULL AND outcome_json IS NOT NULL AND error_code IS NULL)
                OR
                (status IN ('failed','outcome_unknown') AND dispatch_started_at IS NOT NULL
                    AND finished_at IS NOT NULL AND outcome_json IS NULL AND error_code IS NOT NULL)
            )
        );
        CREATE INDEX idx_agent_run_integration_dispatches_owner
            ON agent_run_integration_dispatches(user_id,run_id,status);
        CREATE FUNCTION aibrain_validate_agent_run_integration_dispatch_insert()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.status <> 'prepared' OR NOT EXISTS (
                SELECT 1 FROM agent_run_integration_bindings b
                JOIN agent_run_steps s ON s.id=b.step_id AND s.user_id=b.user_id
                JOIN agent_runs r ON r.id=b.run_id AND r.user_id=b.user_id
                JOIN integration_connections c ON c.id=b.connection_id AND c.user_id=b.user_id
                JOIN users u ON u.id=b.user_id
                WHERE b.step_id=NEW.step_id AND b.user_id=NEW.user_id
                  AND b.run_id=NEW.run_id AND b.connection_id=NEW.connection_id
                  AND b.integration_id=NEW.integration_id AND b.tool_id=NEW.tool_id
                  AND b.contract_fingerprint=NEW.contract_fingerprint
                  AND s.status='running' AND r.status='running' AND u.deleted_at IS NULL
                  AND c.integration_id=b.integration_id AND c.status='active'
                  AND (c.expires_at IS NULL OR c.expires_at>NEW.created_at)
                  AND NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements_text(b.required_scopes_json::jsonb) requested(scope)
                    WHERE NOT EXISTS (
                        SELECT 1 FROM integration_connection_grants g
                        WHERE g.user_id=b.user_id AND g.connection_id=b.connection_id
                          AND g.scope=requested.scope AND g.status='active'
                          AND g.revoked_at IS NULL
                          AND (g.expires_at IS NULL OR g.expires_at>NEW.created_at)
                    )
                  )
            ) THEN
                RAISE EXCEPTION 'integration dispatch requires a running bound step and live owner authority'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER validate_agent_run_integration_dispatch_insert
            BEFORE INSERT ON agent_run_integration_dispatches
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_integration_dispatch_insert();
        CREATE FUNCTION aibrain_validate_agent_run_integration_dispatch_transition()
        RETURNS trigger LANGUAGE plpgsql AS $
        DECLARE expected_event TEXT;
        BEGIN
            IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
                OLD.status='prepared' AND NEW.status='dispatch_started'
                AND NEW.dispatch_started_at IS NOT NULL
                AND NEW.finished_at IS NULL AND NEW.outcome_json IS NULL AND NEW.error_code IS NULL
                AND EXISTS (
                    SELECT 1 FROM agent_run_integration_bindings b
                    JOIN agent_run_steps s ON s.id=b.step_id AND s.user_id=b.user_id
                    JOIN agent_runs r ON r.id=b.run_id AND r.user_id=b.user_id
                    JOIN integration_connections c ON c.id=b.connection_id AND c.user_id=b.user_id
                    JOIN users u ON u.id=b.user_id
                    WHERE b.step_id=OLD.step_id AND b.user_id=OLD.user_id
                      AND b.run_id=OLD.run_id AND b.connection_id=OLD.connection_id
                      AND b.integration_id=OLD.integration_id AND b.tool_id=OLD.tool_id
                      AND b.contract_fingerprint=OLD.contract_fingerprint
                      AND s.status='running' AND r.status='running'
                      AND c.integration_id=OLD.integration_id AND c.status='active'
                      AND (c.expires_at IS NULL OR c.expires_at>NEW.dispatch_started_at)
                      AND u.deleted_at IS NULL
                      AND NOT EXISTS (
                        SELECT 1 FROM jsonb_array_elements_text(b.required_scopes_json::jsonb) requested(scope)
                        WHERE NOT EXISTS (
                            SELECT 1 FROM integration_connection_grants g
                            WHERE g.user_id=b.user_id AND g.connection_id=b.connection_id
                              AND g.scope=requested.scope AND g.status='active'
                              AND g.revoked_at IS NULL
                              AND (g.expires_at IS NULL OR g.expires_at>NEW.dispatch_started_at)
                        )
                      )
                )
                AND EXISTS (
                    SELECT 1 FROM agent_run_events e
                    WHERE e.run_id=OLD.run_id AND e.user_id=OLD.user_id
                      AND e.event_type='integration_dispatch_started'
                      AND e.details_json::jsonb ->> 'step_id'=OLD.step_id
                )
            ) AND NOT (
                OLD.status='dispatch_started'
                AND NEW.status IN ('succeeded','failed','outcome_unknown')
                AND NEW.dispatch_started_at=OLD.dispatch_started_at
                AND NEW.finished_at IS NOT NULL
                AND NEW.finished_at>=OLD.dispatch_started_at
                AND EXISTS (
                    SELECT 1 FROM agent_run_events e
                    WHERE e.run_id=OLD.run_id AND e.user_id=OLD.user_id
                      AND e.details_json::jsonb ->> 'step_id'=OLD.step_id
                      AND e.event_type=CASE NEW.status
                          WHEN 'succeeded' THEN 'integration_dispatch_succeeded'
                          WHEN 'failed' THEN 'integration_dispatch_failed'
                          ELSE 'integration_dispatch_outcome_unknown' END
                )
            ) THEN
                RAISE EXCEPTION 'invalid integration dispatch lifecycle transition'
                    USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER validate_agent_run_integration_dispatch_transition
            BEFORE UPDATE OF status ON agent_run_integration_dispatches
            FOR EACH ROW EXECUTE FUNCTION aibrain_validate_agent_run_integration_dispatch_transition();
        CREATE FUNCTION aibrain_reject_agent_run_integration_dispatch_identity_update()
        RETURNS trigger LANGUAGE plpgsql AS $
        BEGIN
            IF NEW.step_id IS DISTINCT FROM OLD.step_id OR NEW.user_id IS DISTINCT FROM OLD.user_id
               OR NEW.run_id IS DISTINCT FROM OLD.run_id OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
               OR NEW.integration_id IS DISTINCT FROM OLD.integration_id OR NEW.tool_id IS DISTINCT FROM OLD.tool_id
               OR NEW.contract_fingerprint IS DISTINCT FROM OLD.contract_fingerprint
               OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'integration dispatch identity is immutable' USING ERRCODE='23514';
            END IF;
            IF OLD.status IN ('succeeded','failed','outcome_unknown') THEN
                RAISE EXCEPTION 'terminal integration dispatches are immutable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $;
        CREATE TRIGGER prevent_agent_run_integration_dispatch_identity_update
            BEFORE UPDATE ON agent_run_integration_dispatches
            FOR EACH ROW EXECUTE FUNCTION aibrain_reject_agent_run_integration_dispatch_identity_update();
        CREATE TRIGGER prevent_agent_run_integration_dispatch_delete
            BEFORE DELETE ON agent_run_integration_dispatches
            FOR EACH ROW EXECUTE FUNCTION aibrain_require_deleted_owner_for_agent_erasure();
        """,
    ),

)


def _validate_migrations(migrations: tuple[PostgresMigration, ...]) -> None:
    versions = [migration.version for migration in migrations]
    if versions != sorted(set(versions)) or any(version < 1 for version in versions):
        raise ValueError("PostgreSQL migration versions must be unique and increasing")
    for migration in migrations:
        if not migration.name.strip() or not migration.sql.strip():
            raise ValueError("PostgreSQL migrations require a name and SQL")


class PostgresMigrationRunner:
    """Apply ordered PostgreSQL migrations under a session advisory lock."""

    def __init__(self, database_url: str, *, connect: Any = None) -> None:
        if not isinstance(database_url, str) or not database_url.startswith(
            ("postgresql://", "postgres://")
        ):
            raise ValueError("PostgreSQL migration runner requires a PostgreSQL URL")
        self.database_url = database_url
        self._connect = connect

    def _connection_factory(self):
        if self._connect is not None:
            return self._connect
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "PostgreSQL support requires the optional 'postgres' dependency"
            ) from exc
        return psycopg.connect

    def migrate(
        self,
        migrations: tuple[PostgresMigration, ...] = MIGRATIONS,
    ) -> int:
        _validate_migrations(migrations)
        connection = self._connection_factory()(self.database_url)
        locked = False
        try:
            connection.execute(
                "SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_ID,)
            )
            connection.commit()
            locked = True
            with connection.transaction():
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            applied = {
                int(row[0])
                for row in connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                ).fetchall()
            }
            # End the read transaction before applying migrations so each
            # migration's transaction context is a top-level commit boundary.
            connection.commit()
            known = {migration.version for migration in migrations}
            unknown = applied - known
            if unknown:
                raise RuntimeError(
                    "Database contains PostgreSQL migration versions unknown "
                    f"to this application: {sorted(unknown)}"
                )
            for migration in migrations:
                if migration.version in applied:
                    continue
                with connection.transaction():
                    connection.execute(migration.sql)
                    connection.execute(
                        "INSERT INTO schema_migrations(version, name) VALUES (%s, %s)",
                        (migration.version, migration.name),
                    )
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()
            return int(row[0])
        finally:
            if locked:
                try:
                    connection.execute(
                        "SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK_ID,)
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
            connection.close()
