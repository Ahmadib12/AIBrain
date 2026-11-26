import re

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
    assert MIGRATIONS[1].version == 2
    assert "CREATE TABLE memory_items" in MIGRATIONS[1].sql
    assert "CREATE TABLE webauthn_credentials" in MIGRATIONS[1].sql
    assert "CREATE TABLE webauthn_challenges" in MIGRATIONS[1].sql
    assert "CREATE TABLE webauthn_recovery_codes" in MIGRATIONS[1].sql
    assert "CREATE TABLE tool_authorizations" in MIGRATIONS[1].sql
    assert "aibrain_require_active_owner" in MIGRATIONS[1].sql
    assert "AS $" in MIGRATIONS[1].sql
    assert MIGRATIONS[2].version == 3
    assert MIGRATIONS[3].version == 4
    assert "CREATE TABLE external_adapter_certifications" in MIGRATIONS[3].sql
    assert MIGRATIONS[4].version == 5
    assert "CREATE TABLE external_adapter_evidence_packages" in MIGRATIONS[4].sql
    assert MIGRATIONS[5].version == 6
    assert "CREATE TABLE trusted_runner_keys" in MIGRATIONS[5].sql
    assert MIGRATIONS[6].version == 7
    assert "CREATE TABLE security_operator_audit_events" in MIGRATIONS[6].sql
    assert MIGRATIONS[7].version == 8
    assert "CREATE TABLE tool_dispatch_recovery_events" in MIGRATIONS[7].sql
    assert MIGRATIONS[8].version == 9
    assert "CREATE TABLE tool_dispatch_lookup_authorizations" in MIGRATIONS[8].sql
    assert MIGRATIONS[9].version == 10
    assert "prevent_tool_dispatch_audit_delete" in MIGRATIONS[9].sql
    assert MIGRATIONS[10].version == 11
    assert "CREATE TABLE tool_execution_reconciliation_events" in MIGRATIONS[10].sql
    assert MIGRATIONS[11].version == 12
    assert "CREATE TABLE memory_consents" in MIGRATIONS[11].sql
    assert "idx_memory_active_consent" in MIGRATIONS[11].sql
    assert "validate_memory_consent_insert" in MIGRATIONS[11].sql
    assert MIGRATIONS[12].version == 13
    assert "CREATE TABLE learning_adaptation_events" in MIGRATIONS[12].sql
    assert "CREATE TABLE learning_evaluations" in MIGRATIONS[12].sql
    assert "validate_learning_adaptation_transition" in MIGRATIONS[12].sql
    for migration in MIGRATIONS[1:13]:
        if "LANGUAGE plpgsql" in migration.sql:
            openings = re.findall(r"\bAS\s+\$\$", migration.sql)
            closings = re.findall(r"\$\$;", migration.sql)
            assert openings, f"migration {migration.version} has no dollar-quoted function body"
            assert len(openings) == len(closings), (
                f"migration {migration.version} has unbalanced function delimiters"
            )
            assert "\n        $;\n" not in migration.sql
    assert "CREATE TABLE tool_execution_attempts" in MIGRATIONS[2].sql
    assert "CREATE TABLE tool_execution_bindings" in MIGRATIONS[2].sql
    assert "CREATE TABLE tool_dispatch_audit_events" in MIGRATIONS[2].sql
    assert "aibrain_validate_dispatch_audit_event" in MIGRATIONS[2].sql


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
            return (len(MIGRATIONS),)
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
    assert runner.migrate() == len(MIGRATIONS)
    statements = [entry[1] for entry in calls if entry[0] == "execute"]
    assert any("pg_advisory_lock" in statement for statement in statements)
    assert any("CREATE TABLE users" in statement for statement in statements)
    assert any("INSERT INTO schema_migrations" in statement for statement in statements)
    assert any("pg_advisory_unlock" in statement for statement in statements)
    assert calls[-1] == ("close",)
