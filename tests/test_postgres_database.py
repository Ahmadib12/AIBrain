from types import SimpleNamespace

import pytest

from backend.app.persistence.contracts import DatabaseProtocol
from backend.app.persistence.postgres.database import PostgresDatabase


class FakeTransaction:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        self.events.append(("begin",))
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.events.append(("end", exc_type is None))
        return False


class FakeRawConnection:
    def __init__(self, events):
        self.events = events
        self.closed = False

    def execute(self, sql, params=None):
        self.events.append(("execute", sql, params))
        return SimpleNamespace(rowcount=1)

    def transaction(self):
        return FakeTransaction(self.events)

    def close(self):
        self.closed = True
        self.events.append(("close",))


def test_postgres_database_implements_database_protocol_without_connecting():
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: None,
    )
    assert isinstance(database, DatabaseProtocol)


def test_postgres_database_adapts_qmark_sql_and_reuses_thread_connection():
    events = []
    raw = FakeRawConnection(events)
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: raw,
    )
    try:
        first = database.connect()
        second = database.connect()
        assert first is second
        cursor = first.execute(
            "SELECT ? AS owner, '?' AS literal WHERE id = ?",
            ("owner-1", "request-1"),
        )
        assert cursor.rowcount == 1
        assert events[0] == (
            "execute",
            "SELECT %s AS owner, '?' AS literal WHERE id = %s",
            ("owner-1", "request-1"),
        )
    finally:
        database.shutdown()
    assert raw.closed


def test_postgres_database_transaction_commits_on_success_and_rolls_back_on_error():
    events = []
    raw = FakeRawConnection(events)
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: raw,
    )
    try:
        with database.transaction():
            database.connect().execute("SELECT ?", (1,))
        assert ("end", True) in events

        with pytest.raises(RuntimeError, match="rollback"):
            with database.transaction():
                raise RuntimeError("rollback")
        assert ("end", False) in events
    finally:
        database.shutdown()


def test_postgres_database_fails_closed_for_sqlite_immediate_transactions():
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: FakeRawConnection([]),
    )
    with pytest.raises(NotImplementedError, match="row-locking"):
        with database.transaction(immediate=True):
            pass
    database.shutdown()


@pytest.mark.parametrize("url", ["sqlite:///./aibrain.db", "mysql://example/aibrain", ""])
def test_postgres_database_rejects_non_postgres_urls(url):
    with pytest.raises(ValueError, match="PostgreSQL URL"):
        PostgresDatabase(url)
