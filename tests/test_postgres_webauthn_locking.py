from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from backend.app.persistence.postgres.database import PostgresDatabase
from backend.app.persistence.webauthn import WebAuthnRepository


class RecordingConnection:
    def __init__(self):
        self.statements = []
        self.closed = False

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        return SimpleNamespace(fetchone=lambda: {"id": "user-1"}, rowcount=1)

    @contextmanager
    def transaction(self):
        yield self

    def close(self):
        self.closed = True


def test_postgres_webauthn_account_guard_locks_owner_row_first():
    raw_connection = RecordingConnection()
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: raw_connection,
    )
    try:
        repository = WebAuthnRepository(database)
        connection = database.connect()
        repository._require_active_user(connection, "user-1")
        sql, params = raw_connection.statements[0]
        assert "FROM users" in sql
        assert "deleted_at IS NULL" in sql
        assert "FOR UPDATE" in sql
        assert params == ("user-1",)
    finally:
        database.shutdown()
    assert raw_connection.closed


def test_postgres_webauthn_transaction_uses_row_lock_strategy_not_immediate():
    raw_connection = RecordingConnection()
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: raw_connection,
    )
    try:
        repository = WebAuthnRepository(database)
        requested = []
        original = database.transaction

        def record_transaction(*, immediate=False):
            requested.append(immediate)
            return original(immediate=immediate)

        database.transaction = record_transaction
        with repository._transaction():
            pass
        assert requested == [False]
    finally:
        database.shutdown()
    assert raw_connection.closed


def test_sqlite_webauthn_transaction_retains_immediate_writer_lock():
    class Database:
        dialect = "sqlite"

        def __init__(self):
            self.requested = []

        @contextmanager
        def transaction(self, *, immediate=False):
            self.requested.append(immediate)
            yield

    database = Database()
    repository = WebAuthnRepository(database)
    with repository._transaction():
        pass
    assert database.requested == [True]


def test_unknown_webauthn_dialect_fails_closed():
    class Database:
        dialect = "unknown"

    repository = WebAuthnRepository(Database())
    with pytest.raises(RuntimeError, match="Unsupported persistence dialect"):
        repository._transaction()
