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
