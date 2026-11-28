import re

from backend.app.persistence.postgres.migrations import (
    MIGRATIONS,
    PostgresMigration,
    PostgresMigrationRunner,
    _validate_migrations,
    _split_sql_statements,
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
    assert MIGRATIONS[13].version == 14
    assert "CREATE TABLE agents" in MIGRATIONS[13].sql
    assert "agent_events" in MIGRATIONS[13].sql
    assert MIGRATIONS[14].version == 15
    assert "validate_agent_status_transition" in MIGRATIONS[14].sql
    assert MIGRATIONS[15].version == 16
    assert "CREATE TABLE agent_capability_grants" in MIGRATIONS[15].sql
    assert "CREATE TABLE agent_tasks" in MIGRATIONS[15].sql
    assert "CREATE TABLE agent_messages" in MIGRATIONS[15].sql
    assert "capability ceiling exceeds active grants" in MIGRATIONS[15].sql
    assert MIGRATIONS[16].version == 17
    assert "task event transition mismatch" in MIGRATIONS[16].sql
    assert "task definition is immutable" in MIGRATIONS[16].sql
    assert MIGRATIONS[17].version == 18
    assert "CREATE TABLE agent_runs" in MIGRATIONS[17].sql
    assert "CREATE TABLE agent_run_steps" in MIGRATIONS[17].sql
    assert "validate_agent_run_step_status_transition" in MIGRATIONS[17].sql
    assert MIGRATIONS[18].version == 19
    assert "CREATE TABLE integration_connections" in MIGRATIONS[18].sql
    assert "validate_integration_connection_insert" in MIGRATIONS[18].sql
    assert "require_active_connection_for_active_grant" in MIGRATIONS[18].sql
    assert MIGRATIONS[19].version == 20
    assert "CREATE TABLE integration_secrets" in MIGRATIONS[19].sql
    assert "erase_integration_secret_on_terminal_connection" in MIGRATIONS[19].sql
    assert MIGRATIONS[20].version == 21
    assert "CREATE TABLE agent_run_integration_bindings" in MIGRATIONS[20].sql
    assert "exact active owner-granted scopes" in MIGRATIONS[20].sql
    assert MIGRATIONS[21].version == 22
    assert "CREATE TABLE agent_run_integration_dispatches" in MIGRATIONS[21].sql
    assert "invalid integration dispatch lifecycle transition" in MIGRATIONS[21].sql
    assert MIGRATIONS[22].version == 23
    assert "'text_generation'" in MIGRATIONS[22].sql
    assert MIGRATIONS[23].version == 24
    assert "CREATE TABLE devices" in MIGRATIONS[23].sql
    assert "prevent_device_for_inactive_user" in MIGRATIONS[23].sql
    assert MIGRATIONS[24].version == 25
    assert "CREATE TABLE device_auth_challenges" in MIGRATIONS[24].sql
    assert "validate_device_challenge_insert" in MIGRATIONS[24].sql
    assert MIGRATIONS[25].version == 26
    assert "ADD COLUMN device_id" in MIGRATIONS[25].sql
    assert "ADD COLUMN auth_method" in MIGRATIONS[25].sql
    assert "ADD COLUMN purpose" in MIGRATIONS[25].sql
    assert MIGRATIONS[26].version == 27
    assert "CREATE TABLE device_security_events" in MIGRATIONS[26].sql
    assert MIGRATIONS[27].version == 28
    assert "audit_device_enrollment" in MIGRATIONS[27].sql
    assert "device security events may only be erased with the account" in MIGRATIONS[27].sql
    assert MIGRATIONS[28].version == 29
    assert "device identity fields are immutable" in MIGRATIONS[28].sql
    assert "invalid device lifecycle transition" in MIGRATIONS[28].sql
    assert MIGRATIONS[29].version == 30
    assert "validate_session_device_binding" in MIGRATIONS[29].sql
    assert "session revocation is irreversible" in MIGRATIONS[29].sql
    assert MIGRATIONS[30].version == 31
    assert "CREATE TABLE session_security_events" in MIGRATIONS[30].sql
    assert "audit_session_created" in MIGRATIONS[30].sql
    assert MIGRATIONS[31].version == 32
    assert "CREATE TABLE device_key_rotation_challenges" in MIGRATIONS[31].sql
    assert "device key replacement requires verified rotation" in MIGRATIONS[31].sql
    assert MIGRATIONS[32].version == 33
    assert "recovery_code_id" in MIGRATIONS[32].sql
    assert MIGRATIONS[33].version == 34
    assert "CREATE TABLE security_notification_outbox" in MIGRATIONS[33].sql
    assert "enqueue_device_recovery_notification" in MIGRATIONS[33].sql
    assert MIGRATIONS[34].version == 35
    assert "failed_at" in MIGRATIONS[34].sql
    assert MIGRATIONS[35].version == 36
    assert MIGRATIONS[36].version == 37
    assert MIGRATIONS[37].version == 38
    assert MIGRATIONS[38].version == 39
    assert "redrive_count" in MIGRATIONS[35].sql
    assert "claim_token" in MIGRATIONS[35].sql
    assert "security_notification_operator_events" in MIGRATIONS[35].sql
    assert "prevent_security_notification_operator_event_update" in MIGRATIONS[35].sql
    assert "security_recovery_abuse_windows" in MIGRATIONS[35].sql
    for migration in MIGRATIONS[1:36]:
        if "LANGUAGE plpgsql" in migration.sql:
            openings = re.findall(r"\bAS\s+\$\$", migration.sql)
            closings = re.findall(r"\$\$;", migration.sql)
            assert openings, f"migration {migration.version} has no dollar-quoted function body"
            assert len(openings) == len(closings), (
                f"migration {migration.version} has unbalanced function delimiters"
            )
            assert not re.search(r"(?m)^[ \t]*(?<!\$)\$(?!\$)[ \t]*;[ \t]*$", migration.sql), (
                f"migration {migration.version} contains a single-dollar function terminator"
            )
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


def test_postgres_sql_splitter_preserves_procedural_bodies_and_quoted_semicolons():
    sql = """
    -- A comment; must not split this statement.
    CREATE TABLE sample (value TEXT DEFAULT 'left;right');
    CREATE FUNCTION sample_fn() RETURNS trigger LANGUAGE plpgsql AS $body$
    BEGIN
        PERFORM 'inside;body';
        /* nested comment; /* still a comment; */ done */
        RETURN NEW;
    END;
    $body$;
    SELECT "semi;colon" FROM sample;
    """
    statements = _split_sql_statements(sql)
    assert len(statements) == 3
    assert "CREATE TABLE sample (value TEXT DEFAULT 'left;right')" in statements[0]
    assert "PERFORM 'inside;body';" in statements[1]
    assert "nested comment; /* still a comment; */ done" in statements[1]
    assert statements[1].endswith("$body$")
    assert statements[2] == 'SELECT "semi;colon" FROM sample'


def test_postgres_sql_splitter_splits_migration_32_alter_statements():
    statements = _split_sql_statements(MIGRATIONS[31].sql)
    assert statements[0].startswith("ALTER TABLE device_security_events")
    assert "DROP CONSTRAINT" in statements[0]
    assert statements[1].startswith("ALTER TABLE device_security_events")
    assert "ADD CONSTRAINT" in statements[1]
    assert any("CREATE FUNCTION aibrain_validate_device_rotation" in item for item in statements)
