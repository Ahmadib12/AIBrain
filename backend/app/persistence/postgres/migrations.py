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
        AS $
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
