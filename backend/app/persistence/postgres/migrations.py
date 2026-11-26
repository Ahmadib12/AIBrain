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
