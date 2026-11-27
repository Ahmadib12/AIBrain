from contextlib import contextmanager

import pytest

from backend.app.persistence.tool_requests import ToolRequestRepository


class RecordingCursor:
    rowcount = 1

    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class RecordingConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        self.statements.append((" ".join(sql.split()), params))
        if "FROM users" in sql:
            return RecordingCursor({"id": "owner"})
        if "FROM tool_requests" in sql:
            return RecordingCursor({"id": "request"})
        raise AssertionError(f"Unexpected SQL: {sql}")


class RecordingDatabase:
    dialect = "postgresql"

    def __init__(self):
        self.connection = RecordingConnection()
        self.transaction_calls = []

    @contextmanager
    def transaction(self, *, immediate=False):
        self.transaction_calls.append(immediate)
        yield self

    def connect(self):
        return self.connection


def test_postgres_request_transition_locks_owner_then_request():
    database = RecordingDatabase()
    repository = ToolRequestRepository(database)

    with repository._request_transaction("owner", "request"):
        pass

    assert database.transaction_calls == [False]
    statements = database.connection.statements
    assert len(statements) == 2
    assert statements[0][0] == (
        "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE"
    )
    assert statements[0][1] == ("owner",)
    assert statements[1][0] == (
        "SELECT id FROM tool_requests WHERE id = ? AND user_id = ? FOR UPDATE"
    )
    assert statements[1][1] == ("request", "owner")


def test_postgres_request_transition_fails_closed_for_missing_owner():
    database = RecordingDatabase()
    database.connection.execute = lambda sql, params=(): RecordingCursor(None)
    repository = ToolRequestRepository(database)

    with pytest.raises(LookupError, match="Tool request not found"):
        with repository._request_transaction("owner", "request"):
            pass

    assert database.transaction_calls == [False]
    assert len(database.connection.statements) == 0


def test_unknown_persistence_dialect_fails_closed():
    class UnknownDatabase(RecordingDatabase):
        dialect = "unknown"

    repository = ToolRequestRepository(UnknownDatabase())

    with pytest.raises(RuntimeError, match="Unsupported persistence dialect"):
        with repository._request_transaction("owner", "request"):
            pass


class RecoveryCursor:
    rowcount = 1

    def __init__(self, row=None, rows=None):
        self._row = row
        self._rows = rows or []

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._rows


class RecoveryRecordingConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if "FROM tool_execution_attempts AS a" in sql and "JOIN tool_requests AS r" not in sql:
            return RecoveryCursor(rows=[{
                "request_id": "request",
                "user_id": "owner",
            }])
        if "FROM users" in sql:
            return RecoveryCursor({"id": "owner"})
        if "FROM tool_requests" in sql and "FOR UPDATE" in sql:
            return RecoveryCursor({"id": "request"})
        if "FROM tool_execution_attempts AS a" in sql and "JOIN tool_requests AS r" in sql:
            return RecoveryCursor({
                "request_id": "request",
                "user_id": "owner",
                "claimed_at": "2026-01-01T00:00:00+00:00",
                "action_digest": None,
                "adapter_id": None,
                "adapter_version": None,
                "provider_id": None,
                "provider_scope": None,
                "dispatch_started": 0,
            })
        if sql.lstrip().startswith("UPDATE "):
            return RecoveryCursor()
        raise AssertionError(f"Unexpected SQL: {sql}")


class RecoveryRecordingDatabase(RecordingDatabase):
    def __init__(self):
        super().__init__()
        self.connection = RecoveryRecordingConnection()


def test_postgres_stale_recovery_locks_owner_then_request_before_transition():
    database = RecoveryRecordingDatabase()
    repository = ToolRequestRepository(database)

    recovered = repository.recover_stale_execution_attempts(
        stale_before="2026-01-02T00:00:00+00:00"
    )

    assert recovered == 1
    assert database.transaction_calls == [False]
    statements = database.connection.statements
    assert "ORDER BY a.user_id, a.request_id" in statements[0][0]
    assert statements[1][0] == (
        "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE"
    )
    assert statements[2][0] == (
        "SELECT id FROM tool_requests WHERE id = ? AND user_id = ? FOR UPDATE"
    )
    assert "a.status = 'claimed' AND a.claimed_at < ?" in statements[3][0]
    assert statements[4][0].startswith("UPDATE tool_execution_attempts")
    assert statements[5][0].startswith("UPDATE tool_requests")
