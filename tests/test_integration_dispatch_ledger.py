import sqlite3

import pytest

from backend.app.persistence.database import Database


def test_integration_dispatch_ledger_migration_is_applied_after_bindings():
    database = Database("sqlite:///:memory:")
    connection = database.connect()

    versions = [
        row["version"]
        for row in connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]
    assert versions == list(range(1, 37))

    tables = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "agent_run_integration_bindings" in tables
    assert "agent_run_integration_dispatches" in tables

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(agent_run_integration_dispatches)"
        ).fetchall()
    }
    assert {
        "step_id",
        "user_id",
        "run_id",
        "connection_id",
        "integration_id",
        "tool_id",
        "contract_fingerprint",
        "status",
        "dispatch_started_at",
        "finished_at",
        "outcome_json",
        "error_code",
        "created_at",
        "updated_at",
    }.issubset(columns)


def test_integration_dispatch_ledger_rejects_unknown_status_values():
    database = Database("sqlite:///:memory:")
    connection = database.connect()
    # Isolate the table CHECK from the BEFORE INSERT authority trigger, which
    # otherwise rejects this deliberately incomplete row first.
    connection.execute(
        "DROP TRIGGER validate_agent_run_integration_dispatch_insert"
    )

    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        connection.execute(
            """INSERT INTO agent_run_integration_dispatches
               (step_id,user_id,run_id,connection_id,integration_id,tool_id,
                contract_fingerprint,status,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,'retrying',?,?)""",
            (
                "step", "owner", "run", "connection", "provider", "tool",
                "a" * 64, "2026-11-24T00:00:00+00:00",
                "2026-11-24T00:00:00+00:00",
            ),
        )
