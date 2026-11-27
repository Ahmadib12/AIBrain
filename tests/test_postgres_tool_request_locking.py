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


class KeyRevocationConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if "FROM trusted_runner_keys" in sql:
            return RecoveryCursor({"key_id": "runner-key"})
        if "FROM trusted_runner_key_revocations" in sql:
            return RecoveryCursor(None)
        if sql.lstrip().startswith("INSERT INTO trusted_runner_key_revocations"):
            return RecoveryCursor()
        raise AssertionError(f"Unexpected SQL: {sql}")


def test_postgres_trusted_runner_revocation_locks_key_before_insert():
    database = RecordingDatabase()
    database.connection = KeyRevocationConnection()
    repository = ToolRequestRepository(database)

    repository.revoke_trusted_runner_key(
        "runner-key",
        revoked_by="operator",
        reason="Key reported compromised",
    )

    assert database.transaction_calls == [False]
    statements = database.connection.statements
    assert statements[0][0] == (
        "SELECT key_id FROM trusted_runner_keys WHERE key_id = ? FOR UPDATE"
    )
    assert statements[1][0] == (
        "SELECT 1 FROM trusted_runner_key_revocations WHERE key_id = ?"
    )
    assert statements[2][0].startswith(
        "INSERT INTO trusted_runner_key_revocations"
    )


def test_operator_write_transaction_fails_closed_for_unknown_dialect():
    class UnknownDatabase(RecordingDatabase):
        dialect = "unknown"

    repository = ToolRequestRepository(UnknownDatabase())

    with pytest.raises(RuntimeError, match="Unsupported persistence dialect"):
        with repository._operator_write_transaction():
            pass



class EvidenceLifecycleConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if "FROM trusted_runner_keys" in sql:
            return RecoveryCursor({"key_id": params[0]})
        if "FROM external_adapter_evidence_packages" in sql:
            return RecoveryCursor({"id": params[0]})
        if "FROM external_adapter_certifications" in sql:
            return RecoveryCursor({"id": params[0]})
        if "FROM external_adapter_certification_revocations" in sql:
            return RecoveryCursor(None)
        if sql.lstrip().startswith("INSERT INTO external_adapter_certification_revocations"):
            return RecoveryCursor()
        raise AssertionError(f"Unexpected SQL: {sql}")


def test_postgres_evidence_lifecycle_locks_runner_key_before_package():
    database = RecordingDatabase()
    database.connection = EvidenceLifecycleConnection()
    repository = ToolRequestRepository(database)

    with repository._operator_write_transaction() as connection:
        repository._lock_runner_key_and_evidence_package(
            connection, "runner-key", "evidence-package"
        )

    assert database.transaction_calls == [False]
    statements = database.connection.statements
    assert statements[0] == (
        "SELECT key_id FROM trusted_runner_keys WHERE key_id = ? FOR UPDATE",
        ("runner-key",),
    )
    assert statements[1] == (
        "SELECT id FROM external_adapter_evidence_packages WHERE id = ? FOR UPDATE",
        ("evidence-package",),
    )


def test_postgres_evidence_lifecycle_fails_closed_if_runner_key_missing():
    database = RecordingDatabase()
    database.connection = EvidenceLifecycleConnection()
    database.connection.execute = lambda sql, params=(): RecoveryCursor(None)
    repository = ToolRequestRepository(database)

    with repository._operator_write_transaction() as connection:
        with pytest.raises(PermissionError, match="signer key"):
            repository._lock_runner_key_and_evidence_package(
                connection, "missing-key", "evidence-package"
            )


def test_postgres_certification_revocation_locks_certificate_before_insert():
    database = RecordingDatabase()
    database.connection = EvidenceLifecycleConnection()
    repository = ToolRequestRepository(database)

    repository.revoke_external_adapter_certification(
        "certification",
        revoked_by="operator",
        reason="Compromised certification",
    )

    assert database.transaction_calls == [False]
    statements = database.connection.statements
    assert statements[0] == (
        "SELECT id FROM external_adapter_certifications WHERE id = ? FOR UPDATE",
        ("certification",),
    )
    assert statements[1][0].startswith(
        "SELECT 1 FROM external_adapter_certification_revocations"
    )
    assert statements[2][0].startswith(
        "INSERT INTO external_adapter_certification_revocations"
    )


class OperatorHistoryConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if normalized == "SELECT user_id FROM tool_requests WHERE id = ?":
            return RecoveryCursor({"user_id": "owner"})
        if normalized == (
            "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE"
        ):
            return RecoveryCursor({"id": "owner"})
        if normalized == (
            "SELECT 1 FROM tool_requests WHERE id = ? AND user_id = ?"
        ):
            return RecoveryCursor({"1": 1})
        if "LEFT JOIN tool_execution_attempts AS a" in sql and "FOR UPDATE OF r" in sql:
            return RecoveryCursor({
                "user_id": "owner",
                "tool_id": "example.read",
                "status": "completed",
                "created_at": "2026-01-01T00:00:00+00:00",
                "consumed_at": "2026-01-01T00:01:00+00:00",
                "attempt_status": "completed",
                "claimed_at": "2026-01-01T00:01:00+00:00",
                "finished_at": "2026-01-01T00:01:01+00:00",
                "attempt_error_code": None,
            })
        if "UNION ALL" in sql:
            return RecoveryCursor(rows=[])
        if normalized.startswith("INSERT INTO security_operator_audit_events"):
            return RecoveryCursor()
        raise AssertionError(f"Unexpected SQL: {sql}")


def test_postgres_operator_execution_history_locks_owner_then_request_and_audits():
    database = RecordingDatabase()
    database.connection = OperatorHistoryConnection()
    repository = ToolRequestRepository(database)

    result = repository.get_execution_history_for_operator(
        {
            "id": "operator",
            "email": "operator@example.test",
        },
        "request",
        reason="Investigate reported execution",
        limit=20,
    )

    assert result["request"]["owner_user_id"] == "owner"
    assert result["events"] == []
    assert database.transaction_calls == [False]
    statements = database.connection.statements
    assert statements[0] == (
        "SELECT user_id FROM tool_requests WHERE id = ?",
        ("request",),
    )
    assert statements[1] == (
        "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE",
        ("owner",),
    )
    assert "FOR UPDATE OF r" in statements[2][0]
    assert statements[2][1] == ("request",)
    assert statements[-1][0].startswith(
        "INSERT INTO security_operator_audit_events"
    )


class OwnerWriteConnection:
    def __init__(self, owner):
        self.owner = owner
        self.statements = []

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if normalized == (
            "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE"
        ):
            return RecoveryCursor(self.owner)
        raise AssertionError(f"Unexpected SQL: {sql}")


def test_postgres_owner_write_locks_active_account_before_insert_boundary():
    database = RecordingDatabase()
    database.connection = OwnerWriteConnection({"id": "owner"})
    repository = ToolRequestRepository(database)

    with repository._owner_write_transaction("owner"):
        pass

    assert database.transaction_calls == [False]
    assert database.connection.statements == [(
        "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE",
        ("owner",),
    )]


def test_postgres_owner_write_rejects_tombstoned_or_missing_account():
    database = RecordingDatabase()
    database.connection = OwnerWriteConnection(None)
    repository = ToolRequestRepository(database)

    with pytest.raises(LookupError, match="User not found"):
        with repository._owner_write_transaction("owner"):
            pass

    assert database.transaction_calls == [False]
    assert len(database.connection.statements) == 1


def test_owner_write_fails_closed_for_unknown_dialect():
    class UnknownDatabase(RecordingDatabase):
        dialect = "unknown"

    repository = ToolRequestRepository(UnknownDatabase())

    with pytest.raises(RuntimeError, match="Unsupported persistence dialect"):
        with repository._owner_write_transaction("owner"):
            pass
