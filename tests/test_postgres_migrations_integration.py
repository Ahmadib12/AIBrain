import os
import uuid

import pytest

from backend.app.persistence.postgres.migrations import PostgresMigrationRunner


def test_real_postgres_identity_migration_and_idempotent_upgrade():
    database_url = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database")

    psycopg = pytest.importorskip("psycopg")
    runner = PostgresMigrationRunner(database_url)
    assert runner.migrate() == 1
    assert runner.migrate() == 1

    user_id = str(uuid.uuid4())
    email = f"postgres-migration-{user_id}@example.invalid"
    with psycopg.connect(database_url) as connection:
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO users (
                    id, email, password_salt, password_hash, created_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, email, "salt", "hash", "2026-01-01T00:00:00+00:00"),
            )
            connection.execute(
                """
                INSERT INTO sessions (
                    token_hash, user_id, expires_at, created_at
                ) VALUES (%s, %s, %s, %s)
                """,
                ("token-" + user_id, user_id, "2027-01-01T00:00:00+00:00",
                 "2026-01-01T00:00:00+00:00"),
            )
        with connection.transaction():
            connection.execute(
                "DELETE FROM sessions WHERE token_hash=%s", ("token-" + user_id,)
            )
            connection.execute("DELETE FROM users WHERE id=%s", (user_id,))
        applied = connection.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        ).fetchall()
        assert applied == [(1, "core_identity")]
