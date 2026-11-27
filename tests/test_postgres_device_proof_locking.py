from contextlib import contextmanager
from types import SimpleNamespace

from backend.app.devices.proof import DeviceProofRepository
from backend.app.persistence.postgres.database import PostgresDatabase


class RecordingConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        if "FROM users" in sql:
            row = {"id": "user-1"}
        elif "FROM devices" in sql:
            row = {"id": "device-1", "user_id": "user-1"}
        else:
            row = None
        return SimpleNamespace(fetchone=lambda: row, rowcount=1)


def test_postgres_device_proof_locks_account_before_device():
    connection = RecordingConnection()
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: connection,
    )
    try:
        repository = DeviceProofRepository(database)
        repository._lock_owner_device(connection, "user-1", "device-1")

        statements = [sql for sql, _ in connection.statements]
        assert len(statements) == 2
        assert "FROM users" in statements[0] and "FOR UPDATE" in statements[0]
        assert "FROM devices" in statements[1] and "FOR UPDATE" in statements[1]
    finally:
        database.shutdown()


def test_postgres_device_proof_transactions_do_not_request_sqlite_immediate():
    connection = RecordingConnection()
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: connection,
    )
    try:
        repository = DeviceProofRepository(database)
        with repository._transaction():
            pass
    finally:
        database.shutdown()
