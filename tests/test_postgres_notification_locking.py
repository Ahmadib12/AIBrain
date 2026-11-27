from contextlib import contextmanager

import pytest

from backend.app.persistence.security_notifications import SecurityNotificationOutbox


class RecordingCursor:
    def __init__(self, *, rows=(), rowcount=1):
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class RecordingConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if normalized.startswith("SELECT id FROM security_notification_outbox"):
            return RecordingCursor(rows=[{"id": "notification-1"}])
        if normalized.startswith("SELECT id, event_id"):
            return RecordingCursor(rows=[{
                "id": "notification-1",
                "event_id": "event-1",
                "user_id": "user-1",
                "recipient_email": "owner@example.com",
                "notification_type": "security.test",
                "payload_json": "{}",
                "attempts": 1,
                "created_at": "2026-11-27T00:00:00+00:00",
                "claim_token": params[0] if params else "token",
            }])
        return RecordingCursor(rowcount=1)


class RecordingDatabase:
    def __init__(self, dialect):
        self.dialect = dialect
        self.connection = RecordingConnection()
        self.transaction_modes = []

    @contextmanager
    def transaction(self, immediate=False):
        self.transaction_modes.append(immediate)
        yield

    def connect(self):
        return self.connection


def test_postgres_notification_claim_uses_skip_locked_and_regular_transaction():
    database = RecordingDatabase("postgresql")
    claimed = SecurityNotificationOutbox(database).claim_batch(limit=5)

    assert len(claimed) == 1
    assert database.transaction_modes == [False]
    claim_sql = next(
        sql for sql, _ in database.connection.statements
        if sql.startswith("SELECT id FROM security_notification_outbox")
    )
    assert claim_sql.endswith("FOR UPDATE SKIP LOCKED")


def test_sqlite_notification_claim_preserves_immediate_transaction():
    database = RecordingDatabase("sqlite")
    claimed = SecurityNotificationOutbox(database).claim_batch(limit=5)

    assert len(claimed) == 1
    assert database.transaction_modes == [True]
    claim_sql = next(
        sql for sql, _ in database.connection.statements
        if sql.startswith("SELECT id FROM security_notification_outbox")
    )
    assert "FOR UPDATE" not in claim_sql


def test_notification_claim_fails_closed_for_unknown_dialect():
    database = RecordingDatabase("unknown")
    with pytest.raises(RuntimeError, match="Unsupported persistence dialect"):
        SecurityNotificationOutbox(database).claim_batch()
    assert database.transaction_modes == []
