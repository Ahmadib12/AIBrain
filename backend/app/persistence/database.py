import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone
import uuid


class Database:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        if database_url.startswith("sqlite:///"):
            raw_path = database_url[len("sqlite:///"):]
            if raw_path == ":memory:":
                self._database = ":memory:"
                self._uri = False
            else:
                path = Path(raw_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                self._database = str(path)
                self._uri = False
        else:
            raise ValueError("Only sqlite database URLs are supported")
        self._lock = threading.RLock()
        self._local = threading.local()
        self._connections: set[sqlite3.Connection] = set()
        self._connections_lock = threading.Lock()
        if self._database == ":memory:":
            self._database = (
                f"file:aibrain-{uuid.uuid4().hex}?mode=memory&cache=shared"
            )
            self._uri = True
        self.migrate()

    def connect(self):
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            return connection
        connection = sqlite3.connect(
            self._database,
            check_same_thread=False,
            uri=self._uri,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if self._database != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
        self._local.connection = connection
        with self._connections_lock:
            self._connections.add(connection)
        return connection

    def transaction(self, *, immediate: bool = False):
        return _Transaction(self, immediate=immediate)

    def close(self) -> None:
        with self._lock:
            with self._connections_lock:
                connections = tuple(self._connections)
            for connection in connections:
                connection.close()
            self._connections.clear()
            if hasattr(self._local, "connection"):
                del self._local.connection

    def shutdown(self) -> None:
        self.close()

    def migrate(self) -> None:
        migrations = (
            (
                1,
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT,
                    created_at TEXT NOT NULL,
                    deleted_at TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                """,
            ),
            (
                2,
                """
                CREATE TABLE IF NOT EXISTS memory_items (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    memory_type TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL,
                    expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    observation_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS adaptations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    proposal_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                """,
            ),
            (
                3,
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_requests (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_user
                    ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_memory_user
                    ON memory_items(user_id);
                CREATE INDEX IF NOT EXISTS idx_observation_user
                    ON observations(user_id);
                CREATE INDEX IF NOT EXISTS idx_adaptation_user
                    ON adaptations(user_id);
                CREATE INDEX IF NOT EXISTS idx_tool_request_user
                    ON tool_requests(user_id);
                """,
            ),
            (
                4,
                """
                ALTER TABLE tool_requests
                    ADD COLUMN expires_at TEXT;
                ALTER TABLE tool_requests
                    ADD COLUMN consumed_at TEXT;
                ALTER TABLE tool_requests
                    ADD COLUMN confirmation_id TEXT;
                ALTER TABLE tool_requests
                    ADD COLUMN audit_json TEXT;
                """,
            ),
            (
                5,
                """
                CREATE TRIGGER IF NOT EXISTS prevent_session_for_deleted_user
                BEFORE INSERT ON sessions
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_memory_for_deleted_user
                BEFORE INSERT ON memory_items
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_observation_for_deleted_user
                BEFORE INSERT ON observations
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_adaptation_for_deleted_user
                BEFORE INSERT ON adaptations
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER IF NOT EXISTS prevent_tool_request_for_deleted_user
                BEFORE INSERT ON tool_requests
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;
                """,
            ),
            (
                6,
                """
                ALTER TABLE tool_requests
                    ADD COLUMN contract_fingerprint TEXT;
                """,
            ),
            (
                7,
                """
                CREATE TABLE webauthn_credentials (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL UNIQUE,
                    public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL DEFAULT 0
                        CHECK (sign_count >= 0),
                    transports_json TEXT NOT NULL DEFAULT '[]',
                    device_type TEXT,
                    backed_up INTEGER NOT NULL DEFAULT 0
                        CHECK (backed_up IN (0, 1)),
                    name TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    revoked_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );

                CREATE INDEX idx_webauthn_credentials_user
                    ON webauthn_credentials(user_id);

                CREATE TABLE webauthn_challenges (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    challenge_hash TEXT NOT NULL UNIQUE,
                    purpose TEXT NOT NULL
                        CHECK (purpose IN (
                            'registration',
                            'authentication',
                            'tool_approval',
                            'recovery'
                        )),
                    request_id TEXT,
                    proposal_digest TEXT,
                    contract_fingerprint TEXT,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id)
                );

                CREATE INDEX idx_webauthn_challenges_user
                    ON webauthn_challenges(user_id);

                CREATE INDEX idx_webauthn_challenges_expiry
                    ON webauthn_challenges(expires_at);

                CREATE TABLE webauthn_recovery_codes (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    code_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    used_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );

                CREATE INDEX idx_webauthn_recovery_codes_user
                    ON webauthn_recovery_codes(user_id);

                CREATE TABLE tool_authorizations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    challenge_id TEXT NOT NULL UNIQUE,
                    credential_id TEXT NOT NULL,
                    proposal_digest TEXT NOT NULL,
                    contract_fingerprint TEXT NOT NULL,
                    authorized_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id),
                    FOREIGN KEY(challenge_id)
                        REFERENCES webauthn_challenges(id),
                    FOREIGN KEY(credential_id)
                        REFERENCES webauthn_credentials(id)
                );

                CREATE INDEX idx_tool_authorizations_user
                    ON tool_authorizations(user_id);

                CREATE TRIGGER prevent_webauthn_credential_for_deleted_user
                BEFORE INSERT ON webauthn_credentials
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER prevent_webauthn_challenge_for_deleted_user
                BEFORE INSERT ON webauthn_challenges
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER prevent_webauthn_recovery_code_for_deleted_user
                BEFORE INSERT ON webauthn_recovery_codes
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER prevent_tool_authorization_for_deleted_user
                BEFORE INSERT ON tool_authorizations
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;
                """,
            ),
            (
                8,
                """
                ALTER TABLE tool_requests
                    ADD COLUMN authorization_policy TEXT NOT NULL
                    DEFAULT 'unknown'
                    CHECK (
                        authorization_policy IN (
                            'unknown',
                            'read_only',
                            'passkey'
                        )
                    );
                """,
            ),
            (
                9,
                """
                CREATE TABLE tool_execution_attempts (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL
                        CHECK (
                            status IN (
                                'claimed',
                                'succeeded',
                                'failed',
                                'outcome_unknown'
                            )
                        ),
                    claimed_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    finished_at TEXT,
                    error_code TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id)
                        ON DELETE CASCADE,
                    CHECK (
                        (status = 'claimed' AND finished_at IS NULL)
                        OR
                        (
                            status IN (
                                'succeeded',
                                'failed',
                                'outcome_unknown'
                            )
                            AND finished_at IS NOT NULL
                        )
                    )
                );

                CREATE INDEX idx_tool_execution_attempts_status_claimed
                    ON tool_execution_attempts(status, claimed_at);

                CREATE INDEX idx_tool_execution_attempts_user
                    ON tool_execution_attempts(user_id);

                CREATE TRIGGER prevent_tool_execution_attempt_for_inactive_user
                BEFORE INSERT ON tool_execution_attempts
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM tool_requests AS r
                    JOIN users AS u ON u.id = r.user_id
                    WHERE r.id = NEW.request_id
                      AND r.user_id = NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool execution attempt requires an active request owner'
                    );
                END;
                """,
            ),
            (
                10,
                """
                CREATE TABLE tool_execution_bindings (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    action_digest TEXT NOT NULL
                        CHECK (length(action_digest) = 64),
                    payload_json TEXT NOT NULL,
                    tool_contract_fingerprint TEXT NOT NULL
                        CHECK (length(tool_contract_fingerprint) = 64),
                    adapter_id TEXT NOT NULL,
                    adapter_version TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    provider_scope TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX idx_tool_execution_bindings_user
                    ON tool_execution_bindings(user_id);

                CREATE TRIGGER prevent_tool_execution_binding_insert_unclaimed
                BEFORE INSERT ON tool_execution_bindings
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM tool_requests AS r
                    JOIN tool_execution_attempts AS a
                      ON a.request_id = r.id AND a.user_id = r.user_id
                    JOIN users AS u ON u.id = r.user_id
                    WHERE r.id = NEW.request_id
                      AND r.user_id = NEW.user_id
                      AND r.status = 'executing'
                      AND r.consumed_at IS NOT NULL
                      AND a.status = 'claimed'
                      AND a.idempotency_key = NEW.idempotency_key
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'dispatch binding requires an active claimed execution'
                    );
                END;

                CREATE TRIGGER prevent_tool_execution_binding_update
                BEFORE UPDATE ON tool_execution_bindings
                BEGIN
                    SELECT RAISE(ABORT, 'tool execution bindings are immutable');
                END;

                """,
            ),
            (
                11,
                """
                CREATE TABLE tool_dispatch_audit_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (
                        event_type IN (
                            'dispatch_started',
                            'dispatch_succeeded',
                            'dispatch_failed',
                            'dispatch_unknown',
                            'outcome_lookup'
                        )
                    ),
                    action_digest TEXT NOT NULL CHECK (length(action_digest) = 64),
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id) ON DELETE CASCADE
                );

                CREATE INDEX idx_tool_dispatch_audit_user
                    ON tool_dispatch_audit_events(user_id, created_at);

                CREATE TRIGGER prevent_tool_dispatch_audit_update
                BEFORE UPDATE ON tool_dispatch_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'tool dispatch audit events are immutable');
                END;

                CREATE TRIGGER validate_tool_dispatch_audit_event
                BEFORE INSERT ON tool_dispatch_audit_events
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM tool_requests AS r
                    JOIN tool_execution_attempts AS a
                      ON a.request_id = r.id AND a.user_id = r.user_id
                    JOIN users AS u ON u.id = r.user_id
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
                            SELECT 1 FROM tool_dispatch_audit_events AS prior_start
                            WHERE prior_start.request_id = r.id
                              AND prior_start.user_id = r.user_id
                              AND prior_start.event_type = 'dispatch_started'
                          )
                          AND EXISTS (
                            SELECT 1 FROM tool_execution_bindings AS b
                            WHERE b.request_id = r.id
                              AND b.user_id = r.user_id
                              AND b.action_digest = NEW.action_digest
                              AND b.idempotency_key = r.id
                          )
                        )
                        OR
                        (
                          NEW.event_type IN (
                            'dispatch_succeeded',
                            'dispatch_failed',
                            'dispatch_unknown'
                          )
                          AND r.status = 'executing'
                          AND r.consumed_at IS NOT NULL
                          AND a.status = 'claimed'
                          AND NOT EXISTS (
                            SELECT 1 FROM tool_dispatch_audit_events AS prior_outcome
                            WHERE prior_outcome.request_id = r.id
                              AND prior_outcome.user_id = r.user_id
                              AND prior_outcome.event_type IN (
                                'dispatch_succeeded', 'dispatch_failed', 'dispatch_unknown'
                              )
                          )
                          AND EXISTS (
                            SELECT 1 FROM tool_dispatch_audit_events AS s
                            WHERE s.request_id = r.id
                              AND s.user_id = r.user_id
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
                            SELECT 1 FROM tool_dispatch_audit_events AS s
                            WHERE s.request_id = r.id
                              AND s.user_id = r.user_id
                              AND s.event_type = 'dispatch_started'
                              AND s.action_digest = NEW.action_digest
                          )
                        )
                      )
                )
                BEGIN
                    SELECT RAISE(ABORT, 'dispatch audit event violates execution lifecycle');
                END;
                """
            ),
            (
                12,
                """
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
                        provider_id, adapter_id, adapter_version,
                        provider_scope, tool_id, tool_contract_fingerprint, expires_at
                    );

                CREATE TABLE external_adapter_certification_revocations (
                    id TEXT PRIMARY KEY,
                    certification_id TEXT NOT NULL,
                    revoked_by TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(certification_id)
                        REFERENCES external_adapter_certifications(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX idx_external_adapter_certification_revocations
                    ON external_adapter_certification_revocations(certification_id);

                CREATE TRIGGER prevent_external_adapter_certification_update
                BEFORE UPDATE ON external_adapter_certifications
                BEGIN
                    SELECT RAISE(ABORT, 'adapter certifications are immutable');
                END;

                CREATE TRIGGER prevent_external_adapter_certification_delete
                BEFORE DELETE ON external_adapter_certifications
                BEGIN
                    SELECT RAISE(ABORT, 'adapter certifications are immutable');
                END;

                CREATE TRIGGER prevent_external_adapter_revocation_update
                BEFORE UPDATE ON external_adapter_certification_revocations
                BEGIN
                    SELECT RAISE(ABORT, 'adapter certification revocations are immutable');
                END;

                CREATE TRIGGER prevent_external_adapter_revocation_delete
                BEFORE DELETE ON external_adapter_certification_revocations
                BEGIN
                    SELECT RAISE(ABORT, 'adapter certification revocations are immutable');
                END;
                """
            ),
            (
                13,
                """
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
                    manifest_sha256 TEXT NOT NULL
                        CHECK (length(manifest_sha256) = 64),
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
                    package_id TEXT NOT NULL,
                    artifact_name TEXT NOT NULL,
                    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
                    content BLOB NOT NULL,
                    FOREIGN KEY(package_id)
                        REFERENCES external_adapter_evidence_packages(id)
                        ON DELETE CASCADE,
                    UNIQUE(package_id, artifact_name)
                );

                CREATE INDEX idx_external_adapter_evidence_binding
                    ON external_adapter_evidence_packages(
                        provider_id, adapter_id, adapter_version,
                        provider_scope, tool_id, tool_contract_fingerprint,
                        expires_at
                    );

                CREATE TRIGGER prevent_external_adapter_evidence_update
                BEFORE UPDATE ON external_adapter_evidence_packages
                BEGIN
                    SELECT RAISE(ABORT, 'verified evidence packages are immutable');
                END;

                CREATE TRIGGER prevent_external_adapter_evidence_delete
                BEFORE DELETE ON external_adapter_evidence_packages
                BEGIN
                    SELECT RAISE(ABORT, 'verified evidence packages are immutable');
                END;

                CREATE TRIGGER prevent_external_adapter_evidence_artifact_update
                BEFORE UPDATE ON external_adapter_evidence_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'evidence artifacts are immutable');
                END;

                CREATE TRIGGER prevent_external_adapter_evidence_artifact_delete
                BEFORE DELETE ON external_adapter_evidence_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'evidence artifacts are immutable');
                END;
                """
            ),
            (
                14,
                """
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
                    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
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
                    key_id TEXT NOT NULL,
                    revoked_by TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(key_id) REFERENCES trusted_runner_keys(key_id)
                );

                CREATE INDEX idx_trusted_runner_key_revocations
                    ON trusted_runner_key_revocations(key_id);

                CREATE TRIGGER prevent_trusted_runner_key_update
                BEFORE UPDATE ON trusted_runner_keys
                BEGIN
                    SELECT RAISE(ABORT, 'trusted runner keys are immutable');
                END;

                CREATE TRIGGER prevent_runner_key_revocation_update
                BEFORE UPDATE ON trusted_runner_key_revocations
                BEGIN
                    SELECT RAISE(ABORT, 'runner key revocations are immutable');
                END;

                CREATE TRIGGER prevent_runner_key_revocation_delete
                BEFORE DELETE ON trusted_runner_key_revocations
                BEGIN
                    SELECT RAISE(ABORT, 'runner key revocations are immutable');
                END;

                CREATE TABLE external_adapter_evidence_attestations (
                    id TEXT PRIMARY KEY,
                    package_id TEXT NOT NULL UNIQUE,
                    key_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    nonce TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
                    signature TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    FOREIGN KEY(package_id)
                        REFERENCES external_adapter_evidence_packages(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(key_id) REFERENCES trusted_runner_keys(key_id)
                );

                CREATE INDEX idx_evidence_attestation_key
                    ON external_adapter_evidence_attestations(key_id);

                CREATE TRIGGER prevent_trusted_runner_key_delete
                BEFORE DELETE ON trusted_runner_keys
                BEGIN
                    SELECT RAISE(ABORT, 'trusted runner keys cannot be deleted');
                END;

                CREATE TRIGGER prevent_evidence_attestation_update
                BEFORE UPDATE ON external_adapter_evidence_attestations
                BEGIN
                    SELECT RAISE(ABORT, 'runner attestations are immutable');
                END;

                CREATE TRIGGER prevent_evidence_attestation_delete
                BEFORE DELETE ON external_adapter_evidence_attestations
                BEGIN
                    SELECT RAISE(ABORT, 'runner attestations are immutable');
                END;
                """
            ),
            (
                15,
                """
                CREATE TABLE security_operator_audit_events (
                    id TEXT PRIMARY KEY,
                    actor_user_id TEXT NOT NULL,
                    actor_email TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded')),
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(actor_user_id) REFERENCES users(id)
                );

                CREATE INDEX idx_security_operator_audit_actor
                    ON security_operator_audit_events(actor_user_id, created_at);

                CREATE INDEX idx_security_operator_audit_target
                    ON security_operator_audit_events(target_type, target_id, created_at);

                CREATE TRIGGER prevent_security_operator_audit_update
                BEFORE UPDATE ON security_operator_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'security operator audit events are immutable');
                END;

                CREATE TRIGGER prevent_security_operator_audit_delete
                BEFORE DELETE ON security_operator_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'security operator audit events are immutable');
                END;
                """
            ),
            (
                16,
                """
                CREATE TABLE tool_dispatch_recovery_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL
                        CHECK (event_type = 'dispatch_not_started'),
                    action_digest TEXT NOT NULL
                        CHECK (length(action_digest) = 64),
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX idx_tool_dispatch_recovery_request
                    ON tool_dispatch_recovery_events(request_id, created_at);

                CREATE TRIGGER prevent_tool_dispatch_recovery_update
                BEFORE UPDATE ON tool_dispatch_recovery_events
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool dispatch recovery events are immutable'
                    );
                END;

                CREATE TRIGGER validate_tool_dispatch_recovery_event
                BEFORE INSERT ON tool_dispatch_recovery_events
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM tool_requests AS r
                    JOIN tool_execution_attempts AS a
                      ON a.request_id = r.id AND a.user_id = r.user_id
                    JOIN tool_execution_bindings AS b
                      ON b.request_id = r.id AND b.user_id = r.user_id
                    JOIN users AS u ON u.id = r.user_id
                    WHERE r.id = NEW.request_id
                      AND r.user_id = NEW.user_id
                      AND u.deleted_at IS NULL
                      AND r.status = 'executing'
                      AND r.consumed_at IS NOT NULL
                      AND a.status = 'claimed'
                      AND b.idempotency_key = r.id
                      AND b.action_digest = NEW.action_digest
                      AND NOT EXISTS (
                        SELECT 1
                        FROM tool_dispatch_audit_events AS s
                        WHERE s.request_id = r.id
                          AND s.user_id = r.user_id
                          AND s.event_type = 'dispatch_started'
                      )
                      AND NOT EXISTS (
                        SELECT 1
                        FROM tool_dispatch_recovery_events AS prior
                        WHERE prior.request_id = r.id
                          AND prior.user_id = r.user_id
                      )
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'dispatch recovery event violates execution lifecycle'
                    );
                END;
                """
            ),
            (
                17,
                """
                CREATE TABLE tool_dispatch_lookup_authorizations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    certification_id TEXT NOT NULL,
                    action_digest TEXT NOT NULL
                        CHECK (length(action_digest) = 64),
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(certification_id)
                        REFERENCES external_adapter_certifications(id)
                );

                CREATE INDEX idx_tool_dispatch_lookup_authorizations_request
                    ON tool_dispatch_lookup_authorizations(
                        user_id, request_id, created_at
                    );

                CREATE TRIGGER prevent_tool_dispatch_lookup_authorization_update
                BEFORE UPDATE ON tool_dispatch_lookup_authorizations
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool dispatch lookup authorizations are immutable'
                    );
                END;

                CREATE TRIGGER validate_tool_dispatch_lookup_authorization
                BEFORE INSERT ON tool_dispatch_lookup_authorizations
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM tool_requests AS r
                    JOIN tool_execution_attempts AS a
                      ON a.request_id = r.id AND a.user_id = r.user_id
                    JOIN tool_execution_bindings AS b
                      ON b.request_id = r.id AND b.user_id = r.user_id
                    JOIN tool_dispatch_audit_events AS s
                      ON s.request_id = r.id AND s.user_id = r.user_id
                     AND s.event_type = 'dispatch_started'
                    JOIN external_adapter_certifications AS c
                      ON c.id = NEW.certification_id
                    JOIN users AS u ON u.id = r.user_id
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
                        SELECT 1
                        FROM external_adapter_certification_revocations AS cr
                        WHERE cr.certification_id = c.id
                      )
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'lookup authorization violates execution lifecycle'
                    );
                END;
                """
            ),
            (
                18,
                """
                CREATE TRIGGER prevent_tool_dispatch_lookup_authorization_delete
                BEFORE DELETE ON tool_dispatch_lookup_authorizations
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool dispatch lookup authorizations may only be deleted during account erasure'
                    );
                END;
                """
            ),
            (
                19,
                """
                CREATE TRIGGER prevent_tool_dispatch_audit_delete
                BEFORE DELETE ON tool_dispatch_audit_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool dispatch audit events may only be deleted during account erasure'
                    );
                END;

                CREATE TRIGGER prevent_tool_dispatch_recovery_delete
                BEFORE DELETE ON tool_dispatch_recovery_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool dispatch recovery events may only be deleted during account erasure'
                    );
                END;
                """
            ),
            (
                20,
                """
                CREATE TABLE tool_execution_reconciliation_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (
                        outcome IN ('succeeded', 'failed')
                    ),
                    note TEXT NOT NULL CHECK (
                        length(trim(note)) BETWEEN 1 AND 1000
                    ),
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, request_id),
                    FOREIGN KEY(user_id) REFERENCES users(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(request_id) REFERENCES tool_requests(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX idx_tool_execution_reconciliation_request
                    ON tool_execution_reconciliation_events(
                        user_id, request_id, created_at
                    );

                -- Preserve reconciliation records written by the previous
                -- audit_json implementation before adding lifecycle triggers.
                INSERT INTO tool_execution_reconciliation_events (
                    id, user_id, request_id, outcome, note, error_code, created_at
                )
                SELECT
                    lower(hex(randomblob(16))),
                    r.user_id,
                    r.id,
                    CASE WHEN json_valid(COALESCE(r.audit_json, '{}'))
                        THEN json_extract(
                            r.audit_json, '$.execution_reconciliation.outcome'
                        ) END,
                    CASE WHEN json_valid(COALESCE(r.audit_json, '{}'))
                        THEN json_extract(
                            r.audit_json, '$.execution_reconciliation.note'
                        ) END,
                    CASE WHEN json_valid(COALESCE(r.audit_json, '{}'))
                        THEN json_extract(
                            r.audit_json, '$.execution_reconciliation.error_code'
                        ) END,
                    COALESCE(
                        CASE WHEN json_valid(COALESCE(r.audit_json, '{}'))
                            THEN json_extract(
                                r.audit_json,
                                '$.execution_reconciliation.reconciled_at'
                            ) END,
                        r.updated_at
                    )
                FROM tool_requests AS r
                JOIN users AS u ON u.id = r.user_id
                WHERE CASE WHEN json_valid(COALESCE(r.audit_json, '{}'))
                    THEN json_type(
                        r.audit_json, '$.execution_reconciliation'
                    ) END = 'object'
                  AND CASE WHEN json_valid(COALESCE(r.audit_json, '{}'))
                    THEN json_extract(
                        r.audit_json, '$.execution_reconciliation.outcome'
                    ) END IN ('succeeded', 'failed')
                  AND length(trim(COALESCE(
                    CASE WHEN json_valid(COALESCE(r.audit_json, '{}'))
                        THEN json_extract(
                            r.audit_json, '$.execution_reconciliation.note'
                        ) END,
                    ''
                  ))) BETWEEN 1 AND 1000
                  AND u.deleted_at IS NULL;

                UPDATE tool_requests
                SET audit_json = json_remove(
                    audit_json, '$.execution_reconciliation'
                )
                WHERE CASE WHEN json_valid(COALESCE(audit_json, '{}'))
                    THEN json_type(
                        audit_json, '$.execution_reconciliation'
                    ) END = 'object'
                  AND EXISTS (
                      SELECT 1
                      FROM tool_execution_reconciliation_events AS e
                      WHERE e.user_id = tool_requests.user_id
                        AND e.request_id = tool_requests.id
                  );

                CREATE TRIGGER prevent_tool_execution_reconciliation_update
                BEFORE UPDATE ON tool_execution_reconciliation_events
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool execution reconciliation events are immutable'
                    );
                END;

                CREATE TRIGGER prevent_tool_execution_reconciliation_delete
                BEFORE DELETE ON tool_execution_reconciliation_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'tool execution reconciliation events may only be deleted during account erasure'
                    );
                END;

                CREATE TRIGGER validate_tool_execution_reconciliation_event
                BEFORE INSERT ON tool_execution_reconciliation_events
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM tool_requests AS r
                    JOIN tool_execution_attempts AS a
                      ON a.request_id = r.id AND a.user_id = r.user_id
                    JOIN users AS u ON u.id = r.user_id
                    WHERE r.id = NEW.request_id
                      AND r.user_id = NEW.user_id
                      AND u.deleted_at IS NULL
                      AND r.status = 'outcome_unknown'
                      AND r.consumed_at IS NOT NULL
                      AND a.status = 'outcome_unknown'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM tool_execution_reconciliation_events AS prior
                          WHERE prior.user_id = r.user_id
                            AND prior.request_id = r.id
                      )
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'reconciliation event violates execution lifecycle'
                    );
                END;
                """
            ),
            (
                21,
                """
                CREATE TABLE memory_consents (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    purpose TEXT NOT NULL
                        CHECK (purpose = 'personal_memory'),
                    policy_version INTEGER NOT NULL
                        CHECK (policy_version = 1),
                    retention_days INTEGER
                        CHECK (
                            retention_days IS NULL
                            OR retention_days BETWEEN 1 AND 3650
                        ),
                    granted_at TEXT NOT NULL,
                    revoked_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );

                CREATE UNIQUE INDEX idx_memory_active_consent
                    ON memory_consents(user_id, purpose)
                    WHERE revoked_at IS NULL;

                CREATE INDEX idx_memory_consent_user_history
                    ON memory_consents(user_id, granted_at);

                ALTER TABLE memory_items
                    ADD COLUMN consent_id TEXT
                    REFERENCES memory_consents(id);

                CREATE INDEX idx_memory_items_consent
                    ON memory_items(user_id, consent_id, status, expires_at);

                CREATE TRIGGER prevent_memory_consent_for_deleted_user
                BEFORE INSERT ON memory_consents
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'user account is not active');
                END;

                CREATE TRIGGER prevent_memory_consent_identity_update
                BEFORE UPDATE OF id, user_id, purpose, policy_version, granted_at
                ON memory_consents
                BEGIN
                    SELECT RAISE(ABORT, 'memory consent identity is immutable');
                END;

                CREATE TRIGGER prevent_memory_consent_reactivation
                BEFORE UPDATE OF revoked_at ON memory_consents
                WHEN OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'memory consent revocation is immutable');
                END;

                CREATE TRIGGER prevent_memory_consent_policy_update_after_revoke
                BEFORE UPDATE OF retention_days ON memory_consents
                WHEN OLD.revoked_at IS NOT NULL
                BEGIN
                    SELECT RAISE(ABORT, 'revoked memory consent policy is immutable');
                END;

                CREATE TRIGGER prevent_memory_consent_delete
                BEFORE DELETE ON memory_consents
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'memory consent history may only be deleted during account erasure'
                    );
                END;

                CREATE TRIGGER validate_memory_consent_insert
                BEFORE INSERT ON memory_items
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM memory_consents AS c
                    JOIN users AS u ON u.id = c.user_id
                    WHERE c.id = NEW.consent_id
                      AND c.user_id = NEW.user_id
                      AND c.purpose = 'personal_memory'
                      AND c.revoked_at IS NULL
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'memory creation requires active owner consent'
                    );
                END;

                CREATE TRIGGER validate_memory_consent_update
                BEFORE UPDATE ON memory_items
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM memory_consents AS c
                    JOIN users AS u ON u.id = c.user_id
                    WHERE c.id = NEW.consent_id
                      AND c.user_id = NEW.user_id
                      AND c.purpose = 'personal_memory'
                      AND c.revoked_at IS NULL
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'memory updates require active owner consent'
                    );
                END;
                """
            ),
            (
                22,
                """
                ALTER TABLE adaptations ADD COLUMN expires_at TEXT;

                CREATE TABLE learning_adaptation_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    adaptation_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (
                        event_type IN (
                            'proposed', 'approved', 'rejected',
                            'suspended', 'revoked', 'expired', 'evaluated'
                        )
                    ),
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(adaptation_id) REFERENCES adaptations(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX idx_learning_adaptation_events_owner
                    ON learning_adaptation_events(user_id, adaptation_id, created_at);

                CREATE TABLE learning_evaluations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    adaptation_id TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (
                        outcome IN (
                            'improved', 'no_change', 'regressed', 'inconclusive'
                        )
                    ),
                    metric TEXT NOT NULL CHECK (
                        length(trim(metric)) BETWEEN 1 AND 120
                    ),
                    baseline_value REAL NOT NULL,
                    observed_value REAL NOT NULL,
                    confidence REAL NOT NULL CHECK (
                        confidence >= 0.0 AND confidence <= 1.0
                    ),
                    evidence_json TEXT NOT NULL,
                    source TEXT NOT NULL CHECK (source = 'user_reported'),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(adaptation_id) REFERENCES adaptations(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX idx_learning_evaluations_owner
                    ON learning_evaluations(user_id, adaptation_id, created_at);

                CREATE TRIGGER prevent_learning_adaptation_event_update
                BEFORE UPDATE ON learning_adaptation_events
                BEGIN
                    SELECT RAISE(ABORT, 'learning adaptation events are immutable');
                END;

                CREATE TRIGGER prevent_learning_adaptation_event_delete
                BEFORE DELETE ON learning_adaptation_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'learning adaptation events may only be deleted during account erasure'
                    );
                END;

                CREATE TRIGGER validate_learning_adaptation_transition
                BEFORE UPDATE OF status ON adaptations
                WHEN NOT (
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
                )
                BEGIN
                    SELECT RAISE(ABORT, 'invalid learning adaptation transition');
                END;

                CREATE TRIGGER validate_learning_adaptation_event
                BEFORE INSERT ON learning_adaptation_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM adaptations AS a
                    JOIN users AS u ON u.id = a.user_id
                    WHERE a.id = NEW.adaptation_id
                      AND a.user_id = NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'learning event owner mismatch');
                END;

                CREATE TRIGGER prevent_learning_evaluation_update
                BEFORE UPDATE ON learning_evaluations
                BEGIN
                    SELECT RAISE(ABORT, 'learning evaluations are immutable');
                END;

                CREATE TRIGGER prevent_learning_evaluation_delete
                BEFORE DELETE ON learning_evaluations
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'learning evaluations may only be deleted during account erasure'
                    );
                END;

                CREATE TRIGGER validate_learning_evaluation
                BEFORE INSERT ON learning_evaluations
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM adaptations AS a
                    JOIN users AS u ON u.id = a.user_id
                    WHERE a.id = NEW.adaptation_id
                      AND a.user_id = NEW.user_id
                      AND a.status = 'approved'
                      AND (a.expires_at IS NULL OR a.expires_at > NEW.created_at)
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'evaluation requires an approved owner adaptation'
                    );
                END;
                """
            ),
            (
                23,
                """
                CREATE TABLE agents (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100),
                    description TEXT NOT NULL DEFAULT ''
                        CHECK (length(description) <= 1000),
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                        CHECK (json_valid(metadata_json)),
                    status TEXT NOT NULL DEFAULT 'draft'
                        CHECK (status IN ('draft', 'active', 'suspended', 'terminated')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX idx_agents_owner_created
                    ON agents(user_id, created_at, id);

                CREATE TABLE agent_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    actor_user_id TEXT NOT NULL,
                    event_type TEXT NOT NULL
                        CHECK (event_type IN ('registered')),
                    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                    FOREIGN KEY(actor_user_id) REFERENCES users(id)
                );

                CREATE INDEX idx_agent_events_owner_agent
                    ON agent_events(user_id, agent_id, created_at, id);

                CREATE TRIGGER prevent_agent_identity_update
                BEFORE UPDATE OF id, user_id, created_at ON agents
                BEGIN
                    SELECT RAISE(ABORT, 'agent identity is immutable');
                END;

                CREATE TRIGGER prevent_agent_delete
                BEFORE DELETE ON agents
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'agents may only be deleted during account erasure');
                END;

                CREATE TRIGGER validate_agent_insert
                BEFORE INSERT ON agents
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'agent owner account is not active');
                END;

                CREATE TRIGGER prevent_agent_event_update
                BEFORE UPDATE ON agent_events
                BEGIN
                    SELECT RAISE(ABORT, 'agent events are immutable');
                END;

                CREATE TRIGGER prevent_agent_event_delete
                BEFORE DELETE ON agent_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'agent events may only be deleted during account erasure');
                END;

                CREATE TRIGGER validate_agent_event_insert
                BEFORE INSERT ON agent_events
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM agents AS a
                    JOIN users AS u ON u.id = a.user_id
                    WHERE a.id = NEW.agent_id
                      AND a.user_id = NEW.user_id
                      AND NEW.actor_user_id = NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'agent event owner mismatch');
                END;
                """
            ),
            (
                24,
                """
                DROP TRIGGER IF EXISTS prevent_agent_event_update;
                DROP TRIGGER IF EXISTS prevent_agent_event_delete;
                DROP TRIGGER IF EXISTS validate_agent_event_insert;
                DROP INDEX IF EXISTS idx_agent_events_owner_agent;

                ALTER TABLE agent_events RENAME TO agent_events_v23;

                CREATE TABLE agent_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    actor_user_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (
                        event_type IN (
                            'registered', 'activated', 'suspended',
                            'resumed', 'terminated'
                        )
                    ),
                    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                    FOREIGN KEY(actor_user_id) REFERENCES users(id)
                );

                INSERT INTO agent_events (
                    id, user_id, agent_id, actor_user_id,
                    event_type, details_json, created_at
                )
                SELECT
                    id, user_id, agent_id, actor_user_id,
                    event_type, details_json, created_at
                FROM agent_events_v23;

                DROP TABLE agent_events_v23;

                CREATE INDEX idx_agent_events_owner_agent
                    ON agent_events(user_id, agent_id, created_at, id);

                CREATE TRIGGER prevent_agent_event_update
                BEFORE UPDATE ON agent_events
                BEGIN
                    SELECT RAISE(ABORT, 'agent events are immutable');
                END;

                CREATE TRIGGER prevent_agent_event_delete
                BEFORE DELETE ON agent_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'agent events may only be deleted during account erasure'
                    );
                END;

                CREATE TRIGGER validate_agent_event_insert
                BEFORE INSERT ON agent_events
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM agents AS a
                    JOIN users AS u ON u.id = a.user_id
                    WHERE a.id = NEW.agent_id
                      AND a.user_id = NEW.user_id
                      AND NEW.actor_user_id = NEW.user_id
                      AND u.deleted_at IS NULL
                      AND (
                        (
                          NEW.event_type = 'registered'
                          AND a.status = 'draft'
                          AND json_extract(NEW.details_json, '$.initial_status') = 'draft'
                          AND NOT EXISTS (
                            SELECT 1 FROM agent_events AS prior
                            WHERE prior.agent_id = a.id
                          )
                        )
                        OR
                        (
                          NEW.event_type = 'activated'
                          AND a.status = 'draft'
                          AND json_extract(NEW.details_json, '$.from_status') = 'draft'
                          AND json_extract(NEW.details_json, '$.to_status') = 'active'
                        )
                        OR
                        (
                          NEW.event_type = 'suspended'
                          AND a.status = 'active'
                          AND json_extract(NEW.details_json, '$.from_status') = 'active'
                          AND json_extract(NEW.details_json, '$.to_status') = 'suspended'
                        )
                        OR
                        (
                          NEW.event_type = 'resumed'
                          AND a.status = 'suspended'
                          AND json_extract(NEW.details_json, '$.from_status') = 'suspended'
                          AND json_extract(NEW.details_json, '$.to_status') = 'active'
                        )
                        OR
                        (
                          NEW.event_type = 'terminated'
                          AND a.status IN ('draft', 'active', 'suspended')
                          AND json_extract(NEW.details_json, '$.from_status') = a.status
                          AND json_extract(NEW.details_json, '$.to_status') = 'terminated'
                        )
                      )
                )
                BEGIN
                    SELECT RAISE(ABORT, 'agent event owner or transition mismatch');
                END;

                CREATE TRIGGER validate_agent_status_transition
                BEFORE UPDATE OF status ON agents
                WHEN OLD.status <> NEW.status
                AND NOT EXISTS (
                    SELECT 1 FROM agent_events AS e
                    WHERE e.agent_id = OLD.id
                      AND e.user_id = OLD.user_id
                      AND json_extract(e.details_json, '$.from_status') = OLD.status
                      AND json_extract(e.details_json, '$.to_status') = NEW.status
                      AND (
                        (e.event_type = 'activated' AND OLD.status = 'draft' AND NEW.status = 'active')
                        OR (e.event_type = 'suspended' AND OLD.status = 'active' AND NEW.status = 'suspended')
                        OR (e.event_type = 'resumed' AND OLD.status = 'suspended' AND NEW.status = 'active')
                        OR (e.event_type = 'terminated' AND OLD.status IN ('draft', 'active', 'suspended') AND NEW.status = 'terminated')
                      )
                )
                BEGIN
                    SELECT RAISE(ABORT, 'agent status change requires a matching lifecycle event');
                END;

                CREATE TRIGGER prevent_agent_termination_reversal
                BEFORE UPDATE OF status ON agents
                WHEN OLD.status = 'terminated' AND NEW.status <> 'terminated'
                BEGIN
                    SELECT RAISE(ABORT, 'terminated agents cannot be reactivated');
                END;
                """
            ),
            (
                25,
                """
                CREATE TABLE agent_capability_grants (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    capability TEXT NOT NULL CHECK (capability IN (
                        'research.read', 'notes.read', 'notes.write',
                        'calendar.read', 'calendar.write', 'web.search',
                        'files.read'
                    )),
                    expires_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_agent_grants_owner_agent
                    ON agent_capability_grants(user_id, agent_id, created_at);
                CREATE TABLE agent_capability_revocations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(grant_id) REFERENCES agent_capability_grants(id) ON DELETE CASCADE
                );
                CREATE TABLE agent_tasks (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    title TEXT NOT NULL CHECK (length(trim(title)) BETWEEN 1 AND 160),
                    goal TEXT NOT NULL CHECK (length(goal) <= 4000),
                    context_json TEXT NOT NULL CHECK (json_valid(context_json)),
                    capability_ceiling_json TEXT NOT NULL CHECK (json_valid(capability_ceiling_json)),
                    status TEXT NOT NULL CHECK (status IN (
                        'assigned', 'in_progress', 'completed', 'failed',
                        'cancelled', 'expired'
                    )),
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_agent_tasks_owner_agent
                    ON agent_tasks(user_id, agent_id, status, expires_at);
                CREATE TABLE agent_task_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    actor_user_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(task_id) REFERENCES agent_tasks(id) ON DELETE CASCADE,
                    FOREIGN KEY(actor_user_id) REFERENCES users(id)
                );
                CREATE INDEX idx_agent_task_events_owner_task
                    ON agent_task_events(user_id, task_id, created_at, id);
                CREATE TABLE agent_messages (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    sender_agent_id TEXT NOT NULL,
                    recipient_agent_id TEXT NOT NULL,
                    task_id TEXT,
                    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(sender_agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                    FOREIGN KEY(recipient_agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                    FOREIGN KEY(task_id) REFERENCES agent_tasks(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_agent_messages_owner_recipient
                    ON agent_messages(user_id, recipient_agent_id, created_at, id);
                CREATE TABLE agent_control_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_agent_control_events_owner_agent
                    ON agent_control_events(user_id, agent_id, created_at, id);

                CREATE TRIGGER validate_agent_grant_insert
                BEFORE INSERT ON agent_capability_grants
                WHEN NOT EXISTS (
                    SELECT 1 FROM agents a JOIN users u ON u.id = a.user_id
                    WHERE a.id = NEW.agent_id AND a.user_id = NEW.user_id
                      AND a.status = 'active' AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT, 'grant requires active owned agent'); END;
                CREATE TRIGGER prevent_agent_grant_update
                BEFORE UPDATE ON agent_capability_grants
                BEGIN SELECT RAISE(ABORT, 'capability grants are immutable'); END;
                CREATE TRIGGER prevent_agent_grant_delete
                BEFORE DELETE ON agent_capability_grants
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'grants may only be deleted during account erasure'); END;
                CREATE TRIGGER validate_agent_revocation_insert
                BEFORE INSERT ON agent_capability_revocations
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_capability_grants g
                    JOIN agents a ON a.id=g.agent_id
                    JOIN users u ON u.id=g.user_id
                    WHERE g.id=NEW.grant_id AND g.user_id=NEW.user_id
                      AND a.status <> 'terminated' AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT, 'grant revocation owner mismatch'); END;
                CREATE TRIGGER prevent_agent_revocation_update
                BEFORE UPDATE ON agent_capability_revocations
                BEGIN SELECT RAISE(ABORT, 'grant revocations are immutable'); END;
                CREATE TRIGGER prevent_agent_revocation_delete
                BEFORE DELETE ON agent_capability_revocations
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'revocations may only be deleted during account erasure'); END;

                CREATE TRIGGER validate_agent_task_insert
                BEFORE INSERT ON agent_tasks
                WHEN NOT EXISTS (
                    SELECT 1 FROM agents a JOIN users u ON u.id=a.user_id
                    WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                      AND a.status='active' AND u.deleted_at IS NULL
                )
                OR EXISTS (
                    SELECT 1 FROM json_each(NEW.capability_ceiling_json) c
                    WHERE c.type <> 'text' OR NOT EXISTS (
                        SELECT 1 FROM agent_capability_grants g
                        WHERE g.user_id=NEW.user_id AND g.agent_id=NEW.agent_id
                          AND g.capability=c.value
                          AND (g.expires_at IS NULL OR g.expires_at > NEW.created_at)
                          AND NOT EXISTS (
                              SELECT 1 FROM agent_capability_revocations r
                              WHERE r.grant_id=g.id
                          )
                    )
                )
                BEGIN SELECT RAISE(ABORT, 'task requires active agent and granted capability ceiling'); END;
                CREATE TRIGGER prevent_agent_task_identity_update
                BEFORE UPDATE OF id, user_id, agent_id, created_at ON agent_tasks
                BEGIN SELECT RAISE(ABORT, 'task identity is immutable'); END;
                CREATE TRIGGER prevent_agent_task_delete
                BEFORE DELETE ON agent_tasks
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'tasks may only be deleted during account erasure'); END;
                CREATE TRIGGER validate_agent_task_transition
                BEFORE UPDATE OF status ON agent_tasks
                WHEN OLD.status <> NEW.status AND NOT EXISTS (
                    SELECT 1 FROM agent_task_events e
                    WHERE e.task_id=OLD.id AND e.user_id=OLD.user_id
                      AND json_extract(e.details_json, '$.from_status')=OLD.status
                      AND json_extract(e.details_json, '$.to_status')=NEW.status
                )
                BEGIN SELECT RAISE(ABORT, 'task status change requires matching event'); END;
                CREATE TRIGGER prevent_agent_task_event_update
                BEFORE UPDATE ON agent_task_events
                BEGIN SELECT RAISE(ABORT, 'task events are immutable'); END;
                CREATE TRIGGER prevent_agent_task_event_delete
                BEFORE DELETE ON agent_task_events
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'task events may only be deleted during account erasure'); END;
                CREATE TRIGGER validate_agent_task_event_insert
                BEFORE INSERT ON agent_task_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_tasks t JOIN users u ON u.id=t.user_id
                    WHERE t.id=NEW.task_id AND t.user_id=NEW.user_id
                      AND NEW.actor_user_id=NEW.user_id AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT, 'task event owner mismatch'); END;

                CREATE TRIGGER validate_agent_message_insert
                BEFORE INSERT ON agent_messages
                WHEN NOT EXISTS (
                    SELECT 1 FROM agents s JOIN agents r ON r.id=NEW.recipient_agent_id
                    JOIN users u ON u.id=s.user_id
                    WHERE s.id=NEW.sender_agent_id AND s.user_id=NEW.user_id
                      AND r.user_id=NEW.user_id AND s.status='active'
                      AND r.status='active' AND u.deleted_at IS NULL
                )
                OR (NEW.task_id IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM agent_tasks t
                    WHERE t.id=NEW.task_id AND t.user_id=NEW.user_id
                      AND t.agent_id=NEW.recipient_agent_id
                ))
                BEGIN SELECT RAISE(ABORT, 'message requires same-owner active agents and matching task'); END;
                CREATE TRIGGER prevent_agent_message_update
                BEFORE UPDATE ON agent_messages
                BEGIN SELECT RAISE(ABORT, 'agent messages are immutable'); END;
                CREATE TRIGGER prevent_agent_message_delete
                BEFORE DELETE ON agent_messages
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'messages may only be deleted during account erasure'); END;
                CREATE TRIGGER prevent_agent_control_event_update
                BEFORE UPDATE ON agent_control_events
                BEGIN SELECT RAISE(ABORT, 'agent control events are immutable'); END;
                CREATE TRIGGER prevent_agent_control_event_delete
                BEFORE DELETE ON agent_control_events
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT, 'control events may only be deleted during account erasure'); END;
                CREATE TRIGGER validate_agent_control_event_insert
                BEFORE INSERT ON agent_control_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM agents a JOIN users u ON u.id=a.user_id
                    WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT, 'control event owner mismatch'); END;
                """
            ),
            (
                26,
                """
                DROP TRIGGER IF EXISTS validate_agent_revocation_insert;
                CREATE TRIGGER validate_agent_revocation_insert
                BEFORE INSERT ON agent_capability_revocations
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_capability_grants g
                    JOIN users u ON u.id=g.user_id
                    WHERE g.id=NEW.grant_id AND g.user_id=NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT, 'grant revocation owner mismatch'); END;

                DROP TRIGGER IF EXISTS validate_agent_task_event_insert;
                CREATE TRIGGER validate_agent_task_event_insert
                BEFORE INSERT ON agent_task_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_tasks t JOIN users u ON u.id=t.user_id
                    WHERE t.id=NEW.task_id AND t.user_id=NEW.user_id
                      AND NEW.actor_user_id=NEW.user_id AND u.deleted_at IS NULL
                      AND (
                        (
                          NEW.event_type='assigned' AND t.status='assigned'
                          AND json_extract(NEW.details_json,'$.from_status') IS NULL
                          AND json_extract(NEW.details_json,'$.to_status')='assigned'
                        )
                        OR
                        (
                          json_extract(NEW.details_json,'$.from_status')=t.status
                          AND json_extract(NEW.details_json,'$.to_status')=NEW.event_type
                          AND (
                            (t.status='assigned' AND NEW.event_type IN
                              ('in_progress','completed','failed','cancelled','expired'))
                            OR
                            (t.status='in_progress' AND NEW.event_type IN
                              ('completed','failed','cancelled','expired'))
                          )
                        )
                      )
                )
                BEGIN SELECT RAISE(ABORT, 'task event transition mismatch'); END;

                CREATE TRIGGER prevent_agent_task_content_update
                BEFORE UPDATE OF title, goal, context_json, capability_ceiling_json,
                                 expires_at, agent_id, user_id, created_at ON agent_tasks
                BEGIN SELECT RAISE(ABORT, 'task definition is immutable'); END;
                """
            ),
            (
                27,
                """
                CREATE TABLE agent_runs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    actions_json TEXT NOT NULL CHECK (json_valid(actions_json)),
                    plan_digest TEXT NOT NULL CHECK (length(plan_digest)=64),
                    status TEXT NOT NULL CHECK (status IN (
                        'proposed','authorized','running','completed',
                        'failed','cancelled','expired'
                    )),
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    authorized_at TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE,
                    FOREIGN KEY(task_id) REFERENCES agent_tasks(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_agent_runs_owner_task
                    ON agent_runs(user_id,task_id,created_at,id);
                CREATE INDEX idx_agent_runs_status_expiry
                    ON agent_runs(status,expires_at);

                CREATE TABLE agent_run_steps (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 9),
                    tool_id TEXT NOT NULL,
                    arguments_json TEXT NOT NULL CHECK (json_valid(arguments_json)),
                    contract_fingerprint TEXT NOT NULL CHECK (length(contract_fingerprint)=64),
                    required_capability TEXT,
                    status TEXT NOT NULL CHECK (status IN (
                        'pending','running','completed','failed','skipped'
                    )),
                    tool_request_id TEXT,
                    result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(run_id,ordinal),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(run_id) REFERENCES agent_runs(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_agent_run_steps_owner_run
                    ON agent_run_steps(user_id,run_id,ordinal);

                CREATE TABLE agent_run_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    actor_user_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(run_id) REFERENCES agent_runs(id) ON DELETE CASCADE,
                    FOREIGN KEY(actor_user_id) REFERENCES users(id)
                );
                CREATE INDEX idx_agent_run_events_owner_run
                    ON agent_run_events(user_id,run_id,created_at,id);

                CREATE TRIGGER validate_agent_run_insert
                BEFORE INSERT ON agent_runs
                WHEN NOT EXISTS (
                    SELECT 1 FROM agents a
                    JOIN agent_tasks t ON t.agent_id=a.id AND t.user_id=a.user_id
                    JOIN users u ON u.id=a.user_id
                    WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                      AND a.status='active' AND u.deleted_at IS NULL
                      AND t.id=NEW.task_id AND t.user_id=NEW.user_id
                      AND t.status IN ('assigned','in_progress')
                      AND t.expires_at > NEW.created_at
                )
                BEGIN SELECT RAISE(ABORT,'agent run requires active owned agent and live task'); END;

                CREATE TRIGGER prevent_agent_run_definition_update
                BEFORE UPDATE OF id,user_id,agent_id,task_id,actions_json,plan_digest,
                                 expires_at,created_at ON agent_runs
                BEGIN SELECT RAISE(ABORT,'agent run definition is immutable'); END;
                CREATE TRIGGER prevent_agent_run_delete
                BEFORE DELETE ON agent_runs
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT,'agent runs may only be deleted during account erasure'); END;

                CREATE TRIGGER validate_agent_run_status_transition
                BEFORE UPDATE OF status ON agent_runs
                WHEN OLD.status <> NEW.status
                AND NOT EXISTS (
                    SELECT 1 FROM agent_run_events e
                    WHERE e.run_id=OLD.id AND e.user_id=OLD.user_id
                      AND json_extract(e.details_json,'$.from_status')=OLD.status
                      AND json_extract(e.details_json,'$.to_status')=NEW.status
                )
                BEGIN SELECT RAISE(ABORT,'agent run status change requires matching event'); END;

                CREATE TRIGGER validate_agent_run_step_insert
                BEFORE INSERT ON agent_run_steps
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_runs r JOIN users u ON u.id=r.user_id
                    WHERE r.id=NEW.run_id AND r.user_id=NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT,'agent run step owner mismatch'); END;
                CREATE TRIGGER prevent_agent_run_step_definition_update
                BEFORE UPDATE OF id,user_id,run_id,ordinal,tool_id,arguments_json,
                                 contract_fingerprint,required_capability,created_at
                ON agent_run_steps
                BEGIN SELECT RAISE(ABORT,'agent run step definition is immutable'); END;
                CREATE TRIGGER prevent_agent_run_step_delete
                BEFORE DELETE ON agent_run_steps
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT,'agent run steps may only be deleted during account erasure'); END;

                CREATE TRIGGER validate_agent_run_step_status_transition
                BEFORE UPDATE OF status ON agent_run_steps
                WHEN OLD.status <> NEW.status
                AND NOT EXISTS (
                    SELECT 1 FROM agent_run_events e
                    WHERE e.run_id=OLD.run_id AND e.user_id=OLD.user_id
                      AND json_extract(e.details_json,'$.step_id')=OLD.id
                      AND (
                        (OLD.status='pending' AND (
                            (NEW.status='running' AND e.event_type='step_started')
                            OR (NEW.status='failed' AND e.event_type='step_failed')
                            OR (NEW.status='skipped' AND e.event_type='step_skipped')
                        ))
                        OR
                        (OLD.status='running' AND (
                            (NEW.status='completed' AND e.event_type='step_completed')
                            OR (NEW.status='failed' AND e.event_type='step_failed')
                        ))
                      )
                )
                BEGIN SELECT RAISE(ABORT,'agent run step status change requires matching event'); END;

                CREATE TRIGGER validate_agent_run_event_insert
                BEFORE INSERT ON agent_run_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_runs r JOIN users u ON u.id=r.user_id
                    WHERE r.id=NEW.run_id AND r.user_id=NEW.user_id
                      AND NEW.actor_user_id=NEW.user_id AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT,'agent run event owner mismatch'); END;
                CREATE TRIGGER prevent_agent_run_event_update
                BEFORE UPDATE ON agent_run_events
                BEGIN SELECT RAISE(ABORT,'agent run events are immutable'); END;
                CREATE TRIGGER prevent_agent_run_event_delete
                BEFORE DELETE ON agent_run_events
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT,'agent run events may only be deleted during account erasure'); END;
                """
            ),
            (
                28,
                """
                CREATE TABLE integration_connections (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    integration_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN (
                        'pending_verification','active','revoked','expired','disconnected'
                    )),
                    consent_version TEXT NOT NULL,
                    consented_at TEXT NOT NULL,
                    verified_at TEXT,
                    expires_at TEXT,
                    secret_ref TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(id,user_id)
                );
                CREATE INDEX idx_integration_connections_owner
                    ON integration_connections(user_id,status,created_at);
                CREATE TABLE integration_connection_grants (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending','active','revoked','expired')),
                    expires_at TEXT,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(connection_id,user_id)
                        REFERENCES integration_connections(id,user_id) ON DELETE CASCADE,
                    UNIQUE(connection_id,scope)
                );
                CREATE INDEX idx_integration_grants_owner
                    ON integration_connection_grants(user_id,connection_id,status,scope);
                CREATE TABLE integration_connection_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL CHECK (json_valid(details_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(connection_id,user_id)
                        REFERENCES integration_connections(id,user_id) ON DELETE CASCADE
                );
                CREATE INDEX idx_integration_connection_events_owner
                    ON integration_connection_events(user_id,connection_id,created_at,id);

                CREATE TRIGGER validate_integration_connection_insert
                BEFORE INSERT ON integration_connections
                WHEN NOT EXISTS (
                    SELECT 1 FROM users u
                    WHERE u.id=NEW.user_id AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT,'integration connection requires active owner'); END;

                CREATE TRIGGER require_verified_integration_activation
                BEFORE UPDATE OF status ON integration_connections
                WHEN NEW.status='active'
                  AND (NEW.verified_at IS NULL OR NEW.secret_ref IS NULL
                       OR length(trim(NEW.secret_ref))=0)
                BEGIN SELECT RAISE(ABORT,'integration activation requires trusted verification and secret reference'); END;

                CREATE TRIGGER require_active_connection_for_active_grant
                BEFORE UPDATE OF status ON integration_connection_grants
                WHEN NEW.status='active' AND NOT EXISTS (
                    SELECT 1 FROM integration_connections c
                    WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                      AND c.status='active'
                )
                BEGIN SELECT RAISE(ABORT,'active integration grant requires active connection'); END;

                CREATE TRIGGER prevent_integration_grant_scope_update
                BEFORE UPDATE OF user_id,connection_id,scope,created_at
                ON integration_connection_grants
                BEGIN SELECT RAISE(ABORT,'integration grant definition is immutable'); END;

                CREATE TRIGGER validate_integration_grant_insert
                BEFORE INSERT ON integration_connection_grants
                WHEN NOT EXISTS (
                    SELECT 1 FROM integration_connections c JOIN users u ON u.id=c.user_id
                    WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT,'integration grant owner mismatch'); END;

                CREATE TRIGGER validate_integration_connection_event_insert
                BEFORE INSERT ON integration_connection_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM integration_connections c JOIN users u ON u.id=c.user_id
                    WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                      AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT,'integration connection event owner mismatch'); END;

                CREATE TRIGGER prevent_integration_connection_event_update
                BEFORE UPDATE ON integration_connection_events
                BEGIN SELECT RAISE(ABORT,'integration connection events are immutable'); END;
                CREATE TRIGGER prevent_integration_connection_event_delete
                BEFORE DELETE ON integration_connection_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN SELECT RAISE(ABORT,'integration events may only be deleted during account erasure'); END;
                """
            ),
            (
                29,
                """
                CREATE TABLE integration_secrets (
                    secret_ref TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    integration_id TEXT NOT NULL,
                    nonce BLOB NOT NULL CHECK (length(nonce)=12),
                    ciphertext BLOB NOT NULL CHECK (length(ciphertext)>=16),
                    key_version INTEGER NOT NULL CHECK (key_version>=1),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(connection_id,user_id)
                        REFERENCES integration_connections(id,user_id) ON DELETE CASCADE,
                    UNIQUE(connection_id)
                );
                CREATE INDEX idx_integration_secrets_owner
                    ON integration_secrets(user_id,connection_id);

                DROP TRIGGER IF EXISTS require_verified_integration_activation;
                CREATE TRIGGER require_verified_integration_activation
                BEFORE UPDATE OF status ON integration_connections
                WHEN NEW.status='active'
                  AND (
                    NEW.verified_at IS NULL
                    OR NEW.secret_ref IS NULL
                    OR NOT EXISTS (
                      SELECT 1 FROM integration_secrets s
                      WHERE s.secret_ref=NEW.secret_ref
                        AND s.user_id=NEW.user_id
                        AND s.connection_id=NEW.id
                        AND s.integration_id=NEW.integration_id
                    )
                  )
                BEGIN
                    SELECT RAISE(ABORT,'integration activation requires verified vault credentials');
                END;

                CREATE TRIGGER validate_integration_secret_insert
                BEFORE INSERT ON integration_secrets
                WHEN NOT EXISTS (
                    SELECT 1 FROM integration_connections c
                    JOIN users u ON u.id=c.user_id
                    WHERE c.id=NEW.connection_id AND c.user_id=NEW.user_id
                      AND c.integration_id=NEW.integration_id
                      AND c.status='pending_verification'
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT,'vault secret requires matching pending owner connection');
                END;

                CREATE TRIGGER prevent_integration_secret_identity_update
                BEFORE UPDATE OF secret_ref,user_id,connection_id,integration_id,created_at
                ON integration_secrets
                BEGIN
                    SELECT RAISE(ABORT,'vault secret identity is immutable');
                END;

                CREATE TRIGGER prevent_integration_secret_delete
                BEFORE DELETE ON integration_secrets
                WHEN NOT EXISTS (
                    SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL
                )
                AND NOT EXISTS (
                    SELECT 1 FROM integration_connections c
                    WHERE c.id=OLD.connection_id AND c.user_id=OLD.user_id
                      AND c.status IN ('revoked','disconnected','expired')
                )
                BEGIN
                    SELECT RAISE(ABORT,'vault secrets may only be deleted during revocation or account erasure');
                END;

                CREATE TRIGGER erase_integration_secret_on_terminal_connection
                AFTER UPDATE OF status ON integration_connections
                WHEN NEW.status IN ('revoked','disconnected','expired')
                  AND OLD.status <> NEW.status
                BEGIN
                    DELETE FROM integration_secrets
                    WHERE connection_id=NEW.id AND user_id=NEW.user_id;
                END;
                """
            ),
            (
                30,
                """
                CREATE TABLE agent_run_integration_bindings (
                    step_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    integration_id TEXT NOT NULL,
                    manifest_version TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    contract_fingerprint TEXT NOT NULL
                        CHECK (length(contract_fingerprint)=64),
                    required_scopes_json TEXT NOT NULL
                        CHECK (json_valid(required_scopes_json)),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(step_id) REFERENCES agent_run_steps(id) ON DELETE CASCADE,
                    FOREIGN KEY(connection_id,user_id)
                        REFERENCES integration_connections(id,user_id) ON DELETE CASCADE
                );
                CREATE INDEX idx_agent_run_integration_bindings_owner
                    ON agent_run_integration_bindings(user_id,run_id,step_id);

                CREATE TRIGGER validate_agent_run_integration_binding_insert
                BEFORE INSERT ON agent_run_integration_bindings
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_run_steps s
                    JOIN agent_runs r ON r.id=s.run_id AND r.user_id=s.user_id
                    JOIN integration_connections c
                      ON c.id=NEW.connection_id AND c.user_id=NEW.user_id
                    JOIN users u ON u.id=NEW.user_id
                    WHERE s.id=NEW.step_id AND s.user_id=NEW.user_id
                      AND s.run_id=NEW.run_id AND r.status='proposed'
                      AND s.status='pending' AND u.deleted_at IS NULL
                      AND c.integration_id=NEW.integration_id
                      AND c.status='active'
                      AND (c.expires_at IS NULL OR c.expires_at>NEW.created_at)
                      AND s.tool_id=NEW.tool_id
                      AND s.contract_fingerprint=NEW.contract_fingerprint
                )
                BEGIN
                    SELECT RAISE(ABORT,'integration binding requires matching proposed run, step, and active owner connection');
                END;

                CREATE TRIGGER validate_agent_run_integration_binding_scopes
                BEFORE INSERT ON agent_run_integration_bindings
                WHEN EXISTS (
                    SELECT 1 FROM json_each(NEW.required_scopes_json) requested
                    WHERE NOT EXISTS (
                        SELECT 1 FROM integration_connection_grants g
                        WHERE g.user_id=NEW.user_id
                          AND g.connection_id=NEW.connection_id
                          AND g.scope=requested.value
                          AND g.status='active' AND g.revoked_at IS NULL
                          AND (g.expires_at IS NULL OR g.expires_at>NEW.created_at)
                    )
                )
                OR json_type(NEW.required_scopes_json) <> 'array'
                OR json_array_length(NEW.required_scopes_json)=0
                BEGIN
                    SELECT RAISE(ABORT,'integration binding requires exact active owner-granted scopes');
                END;

                CREATE TRIGGER prevent_agent_run_integration_binding_update
                BEFORE UPDATE ON agent_run_integration_bindings
                BEGIN
                    SELECT RAISE(ABORT,'agent run integration bindings are immutable');
                END;

                CREATE TRIGGER prevent_agent_run_integration_binding_delete
                BEFORE DELETE ON agent_run_integration_bindings
                WHEN NOT EXISTS (
                    SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(ABORT,'agent run integration bindings may only be deleted during account erasure');
                END;
                """
            ),
            (
                31,
                """
                CREATE TABLE agent_run_integration_dispatches (
                    step_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    integration_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    contract_fingerprint TEXT NOT NULL
                        CHECK (length(contract_fingerprint)=64),
                    status TEXT NOT NULL CHECK (status IN (
                        'prepared','dispatch_started','succeeded','failed',
                        'outcome_unknown'
                    )),
                    dispatch_started_at TEXT,
                    finished_at TEXT,
                    outcome_json TEXT
                        CHECK (outcome_json IS NULL OR json_valid(outcome_json)),
                    error_code TEXT CHECK (
                        error_code IS NULL OR (
                            length(error_code) BETWEEN 1 AND 64
                            AND error_code NOT GLOB '*[^A-Z0-9_]*'
                        )
                    ),
created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(step_id) REFERENCES agent_run_steps(id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(connection_id,user_id)
                        REFERENCES integration_connections(id,user_id)
                        ON DELETE CASCADE,
                    CHECK (
                        (status='prepared' AND dispatch_started_at IS NULL
                            AND finished_at IS NULL AND outcome_json IS NULL
                            AND error_code IS NULL)
                        OR
                        (status='dispatch_started' AND dispatch_started_at IS NOT NULL
                            AND finished_at IS NULL AND outcome_json IS NULL
                            AND error_code IS NULL)
                        OR
                        (status='succeeded' AND dispatch_started_at IS NOT NULL
                            AND finished_at IS NOT NULL AND outcome_json IS NOT NULL
                            AND error_code IS NULL)
                        OR
                        (status IN ('failed','outcome_unknown')
                            AND dispatch_started_at IS NOT NULL
                            AND finished_at IS NOT NULL AND outcome_json IS NULL
                            AND error_code IS NOT NULL)
                    )
                );
                CREATE INDEX idx_agent_run_integration_dispatches_owner
                    ON agent_run_integration_dispatches(user_id,run_id,status);

                CREATE TRIGGER validate_agent_run_integration_dispatch_insert
                BEFORE INSERT ON agent_run_integration_dispatches
                WHEN NEW.status <> 'prepared'
                  OR NOT EXISTS (
                    SELECT 1
                    FROM agent_run_integration_bindings b
                    JOIN agent_run_steps s
                      ON s.id=b.step_id AND s.user_id=b.user_id
                    JOIN agent_runs r
                      ON r.id=b.run_id AND r.user_id=b.user_id
                    JOIN integration_connections c
                      ON c.id=b.connection_id AND c.user_id=b.user_id
                    JOIN users u ON u.id=b.user_id
                    WHERE b.step_id=NEW.step_id
                      AND b.user_id=NEW.user_id
                      AND b.run_id=NEW.run_id
                      AND b.connection_id=NEW.connection_id
                      AND b.integration_id=NEW.integration_id
                      AND b.tool_id=NEW.tool_id
                      AND b.contract_fingerprint=NEW.contract_fingerprint
                      AND s.status='running'
                      AND r.status='running'
                      AND u.deleted_at IS NULL
                      AND c.integration_id=b.integration_id
                      AND c.status='active'
                      AND (c.expires_at IS NULL OR c.expires_at>NEW.created_at)
                      AND NOT EXISTS (
                        SELECT 1 FROM json_each(b.required_scopes_json) requested
                        WHERE NOT EXISTS (
                          SELECT 1 FROM integration_connection_grants g
                          WHERE g.user_id=b.user_id
                            AND g.connection_id=b.connection_id
                            AND g.scope=requested.value
                            AND g.status='active' AND g.revoked_at IS NULL
                            AND (g.expires_at IS NULL OR g.expires_at>NEW.created_at)
                        )
                      )
                  )
                BEGIN
                    SELECT RAISE(ABORT,'integration dispatch requires a running bound step and live owner authority');
                END;

                CREATE TRIGGER validate_agent_run_integration_dispatch_transition
                BEFORE UPDATE OF status ON agent_run_integration_dispatches
                WHEN OLD.status <> NEW.status
                  AND NOT (
                    (OLD.status='prepared' AND NEW.status='dispatch_started'
                      AND NEW.dispatch_started_at IS NOT NULL
                      AND NEW.finished_at IS NULL
                      AND NEW.outcome_json IS NULL AND NEW.error_code IS NULL
                      AND EXISTS (
                        SELECT 1
                        FROM agent_run_integration_bindings b
                        JOIN agent_run_steps s
                          ON s.id=b.step_id AND s.user_id=b.user_id
                        JOIN agent_runs r
                          ON r.id=b.run_id AND r.user_id=b.user_id
                        JOIN integration_connections c
                          ON c.id=b.connection_id AND c.user_id=b.user_id
                        JOIN users u ON u.id=b.user_id
                        WHERE b.step_id=OLD.step_id
                          AND b.user_id=OLD.user_id
                          AND b.run_id=OLD.run_id
                          AND b.connection_id=OLD.connection_id
                          AND b.integration_id=OLD.integration_id
                          AND b.tool_id=OLD.tool_id
                          AND b.contract_fingerprint=OLD.contract_fingerprint
                          AND s.status='running'
                          AND r.status='running'
                          AND c.integration_id=OLD.integration_id
                          AND c.status='active'
                          AND (c.expires_at IS NULL OR c.expires_at>NEW.dispatch_started_at)
                          AND u.deleted_at IS NULL
                          AND NOT EXISTS (
                            SELECT 1 FROM json_each(b.required_scopes_json) requested
                            WHERE NOT EXISTS (
                              SELECT 1 FROM integration_connection_grants g
                              WHERE g.user_id=b.user_id
                                AND g.connection_id=b.connection_id
                                AND g.scope=requested.value
                                AND g.status='active' AND g.revoked_at IS NULL
                                AND (g.expires_at IS NULL OR g.expires_at>NEW.dispatch_started_at)
                            )
                          )
                      )
                      AND EXISTS (
                        SELECT 1 FROM agent_run_events e
                        WHERE e.run_id=OLD.run_id AND e.user_id=OLD.user_id
                          AND e.event_type='integration_dispatch_started'
                          AND json_extract(e.details_json,'$.step_id')=OLD.step_id
                      ))
                    OR
                    (OLD.status='dispatch_started'
                      AND NEW.status IN ('succeeded','failed','outcome_unknown')
                      AND NEW.dispatch_started_at=OLD.dispatch_started_at
                      AND NEW.finished_at IS NOT NULL
                      AND NEW.finished_at>=OLD.dispatch_started_at
                      AND EXISTS (
                        SELECT 1 FROM agent_run_events e
                        WHERE e.run_id=OLD.run_id AND e.user_id=OLD.user_id
                          AND json_extract(e.details_json,'$.step_id')=OLD.step_id
                          AND (
                            (NEW.status='succeeded'
                              AND e.event_type='integration_dispatch_succeeded')
                            OR (NEW.status='failed'
                              AND e.event_type='integration_dispatch_failed')
                            OR (NEW.status='outcome_unknown'
                              AND e.event_type='integration_dispatch_outcome_unknown')
                          )
                      ))
                  )
                BEGIN
                    SELECT RAISE(ABORT,'invalid integration dispatch lifecycle transition');
                END;

                CREATE TRIGGER prevent_agent_run_integration_dispatch_identity_update
                BEFORE UPDATE OF step_id,user_id,run_id,connection_id,integration_id,
                                 tool_id,contract_fingerprint,created_at
                ON agent_run_integration_dispatches
                BEGIN
                    SELECT RAISE(ABORT,'integration dispatch identity is immutable');
                END;

                CREATE TRIGGER prevent_agent_run_integration_dispatch_terminal_update
                BEFORE UPDATE ON agent_run_integration_dispatches
                WHEN OLD.status IN ('succeeded','failed','outcome_unknown')
                BEGIN
                    SELECT RAISE(ABORT,'terminal integration dispatches are immutable');
                END;

                CREATE TRIGGER prevent_agent_run_integration_dispatch_delete
                BEFORE DELETE ON agent_run_integration_dispatches
                WHEN NOT EXISTS (
                    SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(ABORT,'integration dispatches may only be deleted during account erasure');
                END;
                """
            ),
            (
                32,
                """
                CREATE TABLE agent_capability_grants_new (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    capability TEXT NOT NULL CHECK (capability IN (
                        'text_generation', 'research.read', 'notes.read',
                        'notes.write', 'calendar.read', 'calendar.write',
                        'web.search', 'files.read'
                    )),
                    expires_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
                );
                INSERT INTO agent_capability_grants_new
                    (id,user_id,agent_id,capability,expires_at,created_at)
                SELECT id,user_id,agent_id,capability,expires_at,created_at
                FROM agent_capability_grants;

                CREATE TABLE agent_capability_revocations_new (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(grant_id) REFERENCES agent_capability_grants_new(id) ON DELETE CASCADE
                );
                INSERT INTO agent_capability_revocations_new
                    (id,user_id,grant_id,reason,created_at)
                SELECT id,user_id,grant_id,reason,created_at
                FROM agent_capability_revocations;

                -- Rebuild referenced grant tables without leaving the task trigger
                -- compiled against the dropped table definitions.
                DROP TRIGGER IF EXISTS validate_agent_task_insert;
                DROP TABLE agent_capability_revocations;
                DROP TABLE agent_capability_grants;
                ALTER TABLE agent_capability_grants_new RENAME TO agent_capability_grants;
                ALTER TABLE agent_capability_revocations_new RENAME TO agent_capability_revocations;

                CREATE INDEX idx_agent_grants_owner_agent
                    ON agent_capability_grants(user_id,agent_id,created_at);
                CREATE TRIGGER validate_agent_grant_insert
                BEFORE INSERT ON agent_capability_grants
                WHEN NOT EXISTS (
                    SELECT 1 FROM agents a JOIN users u ON u.id=a.user_id
                    WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                      AND a.status='active' AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT,'grant requires active owned agent'); END;
                CREATE TRIGGER prevent_agent_grant_update
                BEFORE UPDATE ON agent_capability_grants
                BEGIN SELECT RAISE(ABORT,'capability grants are immutable'); END;
                CREATE TRIGGER prevent_agent_grant_delete
                BEFORE DELETE ON agent_capability_grants
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT,'grants may only be deleted during account erasure'); END;
                CREATE TRIGGER validate_agent_revocation_insert
                BEFORE INSERT ON agent_capability_revocations
                WHEN NOT EXISTS (
                    SELECT 1 FROM agent_capability_grants g
                    JOIN agents a ON a.id=g.agent_id
                    JOIN users u ON u.id=g.user_id
                    WHERE g.id=NEW.grant_id AND g.user_id=NEW.user_id
                      AND a.status<>'terminated' AND u.deleted_at IS NULL
                )
                BEGIN SELECT RAISE(ABORT,'grant revocation owner mismatch'); END;
                CREATE TRIGGER prevent_agent_revocation_update
                BEFORE UPDATE ON agent_capability_revocations
                BEGIN SELECT RAISE(ABORT,'grant revocations are immutable'); END;
                CREATE TRIGGER prevent_agent_revocation_delete
                BEFORE DELETE ON agent_capability_revocations
                WHEN NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.user_id AND deleted_at IS NOT NULL)
                BEGIN SELECT RAISE(ABORT,'revocations may only be deleted during account erasure'); END;

                CREATE TRIGGER validate_agent_task_insert
                BEFORE INSERT ON agent_tasks
                WHEN NOT EXISTS (
                    SELECT 1 FROM agents a JOIN users u ON u.id=a.user_id
                    WHERE a.id=NEW.agent_id AND a.user_id=NEW.user_id
                      AND a.status='active' AND u.deleted_at IS NULL
                )
                OR EXISTS (
                    SELECT 1 FROM json_each(NEW.capability_ceiling_json) c
                    WHERE c.type <> 'text' OR NOT EXISTS (
                        SELECT 1 FROM agent_capability_grants g
                        WHERE g.user_id=NEW.user_id AND g.agent_id=NEW.agent_id
                          AND g.capability=c.value
                          AND (g.expires_at IS NULL OR g.expires_at > NEW.created_at)
                          AND NOT EXISTS (
                              SELECT 1 FROM agent_capability_revocations r
                              WHERE r.grant_id=g.id
                          )
                    )
                )
                BEGIN SELECT RAISE(ABORT, 'task requires active agent and granted capability ceiling'); END;
                """,
            ),
            (
                33,
                """
                CREATE TABLE devices (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    platform TEXT NOT NULL
                        CHECK (platform IN ('android','windows','macos','linux')),
                    app_version TEXT NOT NULL
                        CHECK (length(app_version) BETWEEN 1 AND 50),
                    display_name TEXT,
                    public_key_fingerprint TEXT NOT NULL
                        CHECK (length(public_key_fingerprint) = 64),
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','active','revoked')),
                    enrolled_at TEXT NOT NULL,
                    last_seen_at TEXT,
                    revoked_at TEXT,
                    capability_report_json TEXT NOT NULL DEFAULT '[]',
                    capability_reported_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(user_id, public_key_fingerprint)
                );

                CREATE INDEX idx_devices_owner_status
                    ON devices(user_id, status, enrolled_at);

                CREATE TRIGGER prevent_device_for_inactive_user
                BEFORE INSERT ON devices
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id = NEW.user_id AND deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'device requires an active owner');
                END;
                """,
            ),
            (
                34,
                """
                ALTER TABLE devices ADD COLUMN public_key_b64 TEXT;
                CREATE TABLE device_auth_challenges (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    nonce_hash TEXT NOT NULL CHECK (length(nonce_hash) = 64),
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_device_auth_challenges_expiry
                    ON device_auth_challenges(expires_at, used_at);
                CREATE TRIGGER validate_device_challenge_insert
                BEFORE INSERT ON device_auth_challenges
                WHEN NOT EXISTS (
                    SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id
                    WHERE d.id=NEW.device_id AND d.user_id=NEW.user_id
                      AND d.status='pending' AND d.public_key_b64 IS NOT NULL
                      AND u.deleted_at IS NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'device challenge requires pending keyed device');
                END;
                """,
            ),
            (
                35,
                """
                ALTER TABLE sessions
                    ADD COLUMN device_id TEXT REFERENCES devices(id) ON DELETE CASCADE;
                CREATE INDEX idx_sessions_device_active
                    ON sessions(device_id, revoked_at, expires_at);

                ALTER TABLE device_auth_challenges
                    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'enrollment'
                    CHECK (purpose IN ('enrollment','session'));

                DROP TRIGGER IF EXISTS validate_device_challenge_insert;
                CREATE TRIGGER validate_device_challenge_insert
                BEFORE INSERT ON device_auth_challenges
                WHEN NOT EXISTS (
                    SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id
                    WHERE d.id=NEW.device_id AND d.user_id=NEW.user_id
                      AND d.public_key_b64 IS NOT NULL
                      AND u.deleted_at IS NULL
                      AND (
                        (NEW.purpose='enrollment' AND d.status='pending')
                        OR (NEW.purpose='session' AND d.status='active')
                      )
                )
                BEGIN
                    SELECT RAISE(ABORT, 'device challenge purpose does not match device state');
                END;
                """
            ),
            (
                36,
                """
                CREATE TABLE device_security_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (event_type IN (
                        'device.enrolled',
                        'device.key_registered',
                        'device.activated',
                        'device.revoked',
                        'device.session_authenticated',
                        'device.login_authenticated'
                    )),
                    occurred_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_device_security_events_owner_time
                    ON device_security_events(user_id, occurred_at DESC, id DESC);
                CREATE TRIGGER prevent_device_security_event_update
                BEFORE UPDATE ON device_security_events
                BEGIN
                    SELECT RAISE(ABORT, 'device security events are append-only');
                END;
                """
            ),
            (
                37,
                """
                -- Preserve device audit history when a device is removed. Account
                -- erasure remains the only lifecycle allowed to erase owner events.
                DROP TRIGGER IF EXISTS prevent_device_security_event_update;
                DROP INDEX IF EXISTS idx_device_security_events_owner_time;
                ALTER TABLE device_security_events RENAME TO device_security_events_v36;
                CREATE TABLE device_security_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (event_type IN (
                        'device.enrolled',
                        'device.key_registered',
                        'device.activated',
                        'device.revoked',
                        'device.session_authenticated',
                        'device.login_authenticated'
                    )),
                    occurred_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                INSERT INTO device_security_events
                    (id, user_id, device_id, event_type, occurred_at, details_json)
                SELECT id, user_id, device_id, event_type, occurred_at, details_json
                FROM device_security_events_v36;
                DROP TABLE device_security_events_v36;
                CREATE INDEX idx_device_security_events_owner_time
                    ON device_security_events(user_id, occurred_at DESC, id DESC);

                ALTER TABLE sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'account'
                    CHECK (auth_method IN ('account','device_proof','device_login'));

                CREATE TRIGGER prevent_device_security_event_update
                BEFORE UPDATE ON device_security_events
                BEGIN
                    SELECT RAISE(ABORT, 'device security events are immutable');
                END;
                CREATE TRIGGER prevent_device_security_event_delete
                BEFORE DELETE ON device_security_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id=OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'device security events may only be erased with the account');
                END;

                -- Security events are emitted by the same SQLite transaction as
                -- the state change, eliminating gaps between action and audit.
                CREATE TRIGGER audit_device_enrollment
                AFTER INSERT ON devices
                BEGIN
                    INSERT INTO device_security_events
                        (id,user_id,device_id,event_type,occurred_at,details_json)
                    VALUES (
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
                        substr(lower(hex(randomblob(2))),2) || '-' ||
                        substr('89ab',abs(random()) % 4 + 1,1) ||
                        substr(lower(hex(randomblob(2))),2) || '-' ||
                        lower(hex(randomblob(6))),
                        NEW.user_id,NEW.id,'device.enrolled',NEW.enrolled_at,'{}'
                    );
                END;
                CREATE TRIGGER audit_device_key_registration
                AFTER UPDATE OF public_key_b64 ON devices
                WHEN OLD.public_key_b64 IS NULL AND NEW.public_key_b64 IS NOT NULL
                BEGIN
                    INSERT INTO device_security_events
                        (id,user_id,device_id,event_type,occurred_at,details_json)
                    VALUES (
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6))),
                        NEW.user_id,NEW.id,'device.key_registered',
                        strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),'{}'
                    );
                END;
                CREATE TRIGGER audit_device_activation
                AFTER UPDATE OF status ON devices
                WHEN OLD.status <> 'active' AND NEW.status = 'active'
                BEGIN
                    INSERT INTO device_security_events
                        (id,user_id,device_id,event_type,occurred_at,details_json)
                    VALUES (
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6))),
                        NEW.user_id,NEW.id,'device.activated',
                        strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),'{}'
                    );
                END;
                CREATE TRIGGER audit_device_revocation
                AFTER UPDATE OF status ON devices
                WHEN OLD.status <> 'revoked' AND NEW.status = 'revoked'
                BEGIN
                    INSERT INTO device_security_events
                        (id,user_id,device_id,event_type,occurred_at,details_json)
                    VALUES (
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6))),
                        NEW.user_id,NEW.id,'device.revoked',
                        COALESCE(NEW.revoked_at,strftime('%Y-%m-%dT%H:%M:%f+00:00','now')),'{}'
                    );
                END;
                CREATE TRIGGER audit_device_session
                AFTER INSERT ON sessions
                WHEN NEW.device_id IS NOT NULL
                BEGIN
                    INSERT INTO device_security_events
                        (id,user_id,device_id,event_type,occurred_at,details_json)
                    SELECT
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6))),
                        NEW.user_id,NEW.device_id,
                        CASE NEW.auth_method
                            WHEN 'device_login' THEN 'device.login_authenticated'
                            ELSE 'device.session_authenticated'
                        END,
                        NEW.created_at,'{}'
                    WHERE EXISTS (
                        SELECT 1 FROM devices d
                        WHERE d.id=NEW.device_id AND d.user_id=NEW.user_id AND d.status='active'
                    );
                END;
                """
            ),
            (
                38,
                """
                -- Device identity and trust state are monotonic after enrollment.
                CREATE TRIGGER prevent_device_identity_mutation
                BEFORE UPDATE OF id, user_id, public_key_fingerprint ON devices
                WHEN NEW.id IS NOT OLD.id
                  OR NEW.user_id IS NOT OLD.user_id
                  OR NEW.public_key_fingerprint IS NOT OLD.public_key_fingerprint
                BEGIN
                    SELECT RAISE(ABORT, 'device identity fields are immutable');
                END;

                CREATE TRIGGER prevent_device_public_key_replacement
                BEFORE UPDATE OF public_key_b64 ON devices
                WHEN OLD.public_key_b64 IS NOT NULL
                 AND NEW.public_key_b64 IS NOT OLD.public_key_b64
                BEGIN
                    SELECT RAISE(ABORT, 'registered device public keys are immutable');
                END;

                CREATE TRIGGER validate_device_status_transition
                BEFORE UPDATE OF status ON devices
                WHEN NOT (
                    OLD.status = NEW.status
                    OR (OLD.status = 'pending' AND NEW.status IN ('active','revoked'))
                    OR (OLD.status = 'active' AND NEW.status = 'revoked')
                )
                BEGIN
                    SELECT RAISE(ABORT, 'invalid device lifecycle transition');
                END;
                """
            ),
            (
                39,
                """
                -- A session's authentication provenance and device binding are
                -- immutable. Revocation is one-way and session validity cannot
                -- be extended by rewriting its expiry.
                CREATE TRIGGER validate_session_device_binding
                BEFORE INSERT ON sessions
                WHEN
                    (NEW.device_id IS NULL AND NEW.auth_method <> 'account')
                    OR
                    (NEW.device_id IS NOT NULL AND (
                        NEW.auth_method = 'account'
                        OR NOT EXISTS (
                            SELECT 1 FROM devices d
                            WHERE d.id = NEW.device_id
                              AND d.user_id = NEW.user_id
                              AND d.status = 'active'
                        )
                    ))
                BEGIN
                    SELECT RAISE(ABORT, 'session authentication method and device binding are inconsistent');
                END;

                CREATE TRIGGER prevent_session_identity_mutation
                BEFORE UPDATE OF token_hash, user_id, expires_at, created_at,
                                 device_id, auth_method ON sessions
                WHEN NEW.token_hash IS NOT OLD.token_hash
                  OR NEW.user_id IS NOT OLD.user_id
                  OR NEW.expires_at IS NOT OLD.expires_at
                  OR NEW.created_at IS NOT OLD.created_at
                  OR NEW.device_id IS NOT OLD.device_id
                  OR NEW.auth_method IS NOT OLD.auth_method
                BEGIN
                    SELECT RAISE(ABORT, 'session identity and authentication binding are immutable');
                END;

                CREATE TRIGGER prevent_session_unrevocation
                BEFORE UPDATE OF revoked_at ON sessions
                WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
                BEGIN
                    SELECT RAISE(ABORT, 'session revocation is irreversible');
                END;
                """
            ),
            (
                40,
                """
                -- Session security history is independent of live session rows:
                -- token material is never copied into the audit stream.
                ALTER TABLE sessions ADD COLUMN audit_ref TEXT;
                UPDATE sessions
                SET audit_ref =
                    lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                    lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                    lower(hex(randomblob(6)))
                WHERE audit_ref IS NULL;
                CREATE UNIQUE INDEX idx_sessions_audit_ref ON sessions(audit_ref);

                CREATE TABLE session_security_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    session_ref TEXT NOT NULL,
                    device_id TEXT,
                    auth_method TEXT NOT NULL CHECK (
                        auth_method IN ('account','device_proof','device_login')
                    ),
                    event_type TEXT NOT NULL CHECK (
                        event_type IN (
                            'session.created',
                            'session.revoked',
                            'session.expired'
                        )
                    ),
                    occurred_at TEXT NOT NULL,
                    UNIQUE(session_ref, event_type),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX idx_session_security_events_owner_time
                    ON session_security_events(user_id, occurred_at DESC, id DESC);
                CREATE INDEX idx_session_security_events_session
                    ON session_security_events(user_id, session_ref, occurred_at);

                CREATE TRIGGER prevent_session_security_event_update
                BEFORE UPDATE ON session_security_events
                BEGIN
                    SELECT RAISE(ABORT, 'session security events are immutable');
                END;

                CREATE TRIGGER prevent_session_security_event_delete
                BEFORE DELETE ON session_security_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id=OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(
                        ABORT,
                        'session security events may only be erased with the account'
                    );
                END;

                CREATE TRIGGER prevent_client_session_audit_ref
                BEFORE INSERT ON sessions
                WHEN NEW.audit_ref IS NOT NULL
                BEGIN
                    SELECT RAISE(ABORT, 'session audit reference is server generated');
                END;

                CREATE TRIGGER prevent_session_audit_ref_replacement
                BEFORE UPDATE OF audit_ref ON sessions
                WHEN OLD.audit_ref IS NOT NULL AND NEW.audit_ref IS NOT OLD.audit_ref
                BEGIN
                    SELECT RAISE(ABORT, 'session audit reference is immutable');
                END;

                CREATE TRIGGER audit_session_created
                AFTER INSERT ON sessions
                BEGIN
                    UPDATE sessions
                    SET audit_ref =
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6)))
                    WHERE token_hash=NEW.token_hash AND audit_ref IS NULL;

                    INSERT INTO session_security_events
                        (id,user_id,session_ref,device_id,auth_method,event_type,occurred_at)
                    SELECT
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6))),
                        user_id,audit_ref,device_id,auth_method,'session.created',created_at
                    FROM sessions WHERE token_hash=NEW.token_hash;
                END;

                CREATE TRIGGER audit_session_revoked
                AFTER UPDATE OF revoked_at ON sessions
                WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
                BEGIN
                    INSERT INTO session_security_events
                        (id,user_id,session_ref,device_id,auth_method,event_type,occurred_at)
                    VALUES (
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6))),
                        NEW.user_id,NEW.audit_ref,NEW.device_id,NEW.auth_method,
                        'session.revoked',NEW.revoked_at
                    );
                END;

                CREATE TRIGGER audit_session_expired
                BEFORE DELETE ON sessions
                WHEN datetime(OLD.expires_at) <= CURRENT_TIMESTAMP
                BEGIN
                    INSERT INTO session_security_events
                        (id,user_id,session_ref,device_id,auth_method,event_type,occurred_at)
                    VALUES (
                        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' ||
                        lower(hex(randomblob(6))),
                        OLD.user_id,OLD.audit_ref,OLD.device_id,OLD.auth_method,
                        'session.expired',OLD.expires_at
                    );
                END;
                """
            ),
            (
                41,
                """
                -- A key can change only through a dual-possession, one-time rotation.
                CREATE TABLE device_key_rotation_challenges (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64),
                    proposed_public_key_b64 TEXT NOT NULL,
                    proposed_fingerprint TEXT NOT NULL CHECK(length(proposed_fingerprint)=64),
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    applied_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE INDEX idx_device_key_rotation_expiry
                    ON device_key_rotation_challenges(expires_at, used_at);

                DROP TRIGGER IF EXISTS prevent_device_security_event_update;
                DROP TRIGGER IF EXISTS prevent_device_security_event_delete;
                DROP INDEX IF EXISTS idx_device_security_events_owner_time;
                ALTER TABLE device_security_events RENAME TO device_security_events_v40;
                CREATE TABLE device_security_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    event_type TEXT NOT NULL CHECK (event_type IN (
                        'device.enrolled',
                        'device.key_registered',
                        'device.activated',
                        'device.revoked',
                        'device.session_authenticated',
                        'device.login_authenticated',
                        'device.key_rotated'
                    )),
                    occurred_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                INSERT INTO device_security_events
                    (id,user_id,device_id,event_type,occurred_at,details_json)
                SELECT id,user_id,device_id,event_type,occurred_at,details_json
                FROM device_security_events_v40;
                DROP TABLE device_security_events_v40;
                CREATE INDEX idx_device_security_events_owner_time
                    ON device_security_events(user_id, occurred_at DESC, id DESC);
                CREATE TRIGGER prevent_device_security_event_update
                BEFORE UPDATE ON device_security_events
                BEGIN
                    SELECT RAISE(ABORT, 'device security events are immutable');
                END;
                CREATE TRIGGER prevent_device_security_event_delete
                BEFORE DELETE ON device_security_events
                WHEN NOT EXISTS (
                    SELECT 1 FROM users
                    WHERE id=OLD.user_id AND deleted_at IS NOT NULL
                )
                BEGIN
                    SELECT RAISE(ABORT, 'device security events may only be erased with the account');
                END;

                DROP TRIGGER IF EXISTS prevent_device_identity_mutation;
                DROP TRIGGER IF EXISTS prevent_device_public_key_replacement;
                CREATE TRIGGER prevent_device_identity_mutation
                BEFORE UPDATE OF id, user_id ON devices
                WHEN NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id
                BEGIN
                    SELECT RAISE(ABORT, 'device identity fields are immutable');
                END;
                CREATE TRIGGER prevent_device_key_rotation_without_proof
                BEFORE UPDATE OF public_key_b64, public_key_fingerprint ON devices
                WHEN (NEW.public_key_b64 IS NOT OLD.public_key_b64
                   OR NEW.public_key_fingerprint IS NOT OLD.public_key_fingerprint)
                 AND NOT EXISTS (
                    SELECT 1 FROM device_key_rotation_challenges c
                    WHERE c.device_id=OLD.id AND c.user_id=OLD.user_id
                      AND c.used_at IS NOT NULL AND c.applied_at IS NULL
                      AND c.proposed_public_key_b64=NEW.public_key_b64
                      AND c.proposed_fingerprint=NEW.public_key_fingerprint
                 )
                BEGIN
                    SELECT RAISE(ABORT, 'device key replacement requires verified rotation');
                END;
                """
            ),
        )

        with self._lock:
            for version, script in migrations:
                connection = self.connect()
                exists = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='schema_migrations'"
                ).fetchone()
                if exists is None:
                    connection.execute(
                        "CREATE TABLE schema_migrations "
                        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
                    )
                applied = connection.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = ?",
                    (version,),
                ).fetchone()
                if applied is not None:
                    continue
                self._apply_migration(connection, version, script)

    def _apply_migration(
        self,
        connection,
        version: int,
        script: str,
    ) -> None:
        transaction_started = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction_started = True

            # Another process may have applied this migration while we waited
            # for the SQLite write lock.
            applied = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?",
                (version,),
            ).fetchone()
            if applied is not None:
                connection.commit()
                return

            # executescript() implicitly commits an active transaction.
            # Execute complete statements individually so DDL and the version
            # record remain in the same rollback-capable transaction.
            pending = []
            for line in script.splitlines():
                pending.append(line)
                statement = "\n".join(pending)
                if sqlite3.complete_statement(statement):
                    if statement.strip():
                        connection.execute(statement)
                    pending = []

            remainder = "\n".join(pending).strip()
            if remainder:
                raise ValueError("Incomplete SQL statement in migration")

            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()
        except BaseException:
            if transaction_started:
                connection.rollback()
            raise


class _Transaction:
    def __init__(
        self,
        database: Database,
        *,
        immediate: bool = False,
    ) -> None:
        self.database = database
        self.immediate = immediate

    def __enter__(self):
        self.database._lock.acquire()
        try:
            begin_sql = "BEGIN IMMEDIATE" if self.immediate else "BEGIN"
            self.database.connect().execute(begin_sql)
        except BaseException:
            self.database._lock.release()
            raise
        return self.database

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                self.database.connect().commit()
            else:
                self.database.connect().rollback()
        finally:
            self.database._lock.release()
