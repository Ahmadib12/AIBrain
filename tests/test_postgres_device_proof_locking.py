from contextlib import contextmanager
from types import SimpleNamespace

from backend.app.devices.proof import DeviceProofRepository
from backend.app.persistence.postgres.database import PostgresDatabase
from backend.app.persistence.devices import DeviceRepository


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

    @contextmanager
    def transaction(self):
        yield self

    def close(self):
        pass


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
        requested = []
        original_transaction = database.transaction

        def recording_transaction(*, immediate=False):
            requested.append(immediate)
            return original_transaction(immediate=immediate)

        database.transaction = recording_transaction
        with repository._transaction():
            pass
        assert requested == [False]
    finally:
        database.shutdown()


class RevocationConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=None):
        self.statements.append(sql)
        if "FROM users" in sql or "FROM devices" in sql:
            row = {"id": "row"}
        else:
            row = None
        return SimpleNamespace(fetchone=lambda: row, rowcount=1)


class RevocationDatabase:
    dialect = "postgresql"

    def __init__(self):
        self.connection = RevocationConnection()
        self.immediate_values = []

    @contextmanager
    def transaction(self, *, immediate=False):
        self.immediate_values.append(immediate)
        yield self.connection

    def connect(self):
        return self.connection


class RecordingDeviceRepository(DeviceRepository):
    def get_owned(self, owner_id, device_id):
        return {"device_id": device_id, "owner_id": owner_id}


def test_postgres_device_revocation_locks_account_then_device_and_revokes_sessions():
    database = RevocationDatabase()
    repository = RecordingDeviceRepository(database)

    result = repository.revoke("user-1", "device-1")

    assert result["device_id"] == "device-1"
    sql = database.connection.statements
    account_lock = next(i for i, statement in enumerate(sql) if "FROM users" in statement and "FOR UPDATE" in statement)
    device_lock = next(i for i, statement in enumerate(sql) if "FROM devices" in statement and "FOR UPDATE" in statement)
    device_update = next(i for i, statement in enumerate(sql) if "UPDATE devices" in statement)
    session_update = next(i for i, statement in enumerate(sql) if "UPDATE sessions" in statement)
    assert account_lock < device_lock < device_update < session_update
    assert database.immediate_values == [False]


class DialectTransactionDatabase:
    def __init__(self, dialect):
        self.dialect = dialect
        self.immediate_values = []

    @contextmanager
    def transaction(self, *, immediate=False):
        self.immediate_values.append(immediate)
        yield


def test_sqlite_device_proof_keeps_immediate_transactions():
    database = DialectTransactionDatabase("sqlite")
    repository = DeviceProofRepository(database)

    with repository._transaction():
        pass

    assert database.immediate_values == [True]
