from backend.app.persistence.postgres.migrations import (
    MIGRATIONS,
    PostgresMigration,
    PostgresMigrationRunner,
    _validate_migrations,
)


def test_postgres_migration_stream_starts_with_identity_schema():
    _validate_migrations(MIGRATIONS)
    assert MIGRATIONS[0].version == 1
    assert "CREATE TABLE users" in MIGRATIONS[0].sql
    assert "CREATE TABLE sessions" in MIGRATIONS[0].sql
    assert "REFERENCES users(id)" in MIGRATIONS[0].sql


def test_postgres_migration_versions_must_be_unique_and_increasing():
    migration = PostgresMigration(1, "one", "SELECT 1")
    try:
        _validate_migrations((migration, migration))
    except ValueError as exc:
        assert "unique and increasing" in str(exc)
    else:
        raise AssertionError("duplicate migration versions must be rejected")


def test_postgres_migration_runner_rejects_non_postgres_urls():
    try:
        PostgresMigrationRunner("sqlite:///./aibrain.db")
    except ValueError as exc:
        assert "PostgreSQL URL" in str(exc)
    else:
        raise AssertionError("SQLite URL must not be accepted")


def test_postgres_migration_runner_uses_advisory_lock_and_transactions():
    calls = []

    class FakeTransaction:
        def __enter__(self):
            calls.append(("transaction_begin",))
        def __exit__(self, exc_type, exc, traceback):
            calls.append(("transaction_end", exc_type is None))
            return False

    class FakeConnection:
        def execute(self, sql, params=None):
            calls.append(("execute", " ".join(sql.split()), params))
            normalized = " ".join(sql.split())
            if normalized.startswith("SELECT version FROM schema_migrations"):
                return self
            if normalized.startswith("SELECT COALESCE(MAX(version)"):
                return self
            return self
        def fetchall(self):
            return []
        def fetchone(self):
            return (1,)
        def transaction(self):
            return FakeTransaction()
        def commit(self):
            calls.append(("commit",))
        def rollback(self):
            calls.append(("rollback",))
        def close(self):
            calls.append(("close",))

    connection = FakeConnection()
    runner = PostgresMigrationRunner(
        "postgresql://example.invalid/aibrain",
        connect=lambda url: connection,
    )
    assert runner.migrate() == 1
    statements = [entry[1] for entry in calls if entry[0] == "execute"]
    assert any("pg_advisory_lock" in statement for statement in statements)
    assert any("CREATE TABLE users" in statement for statement in statements)
    assert any("INSERT INTO schema_migrations" in statement for statement in statements)
    assert any("pg_advisory_unlock" in statement for statement in statements)
    assert calls[-1] == ("close",)
