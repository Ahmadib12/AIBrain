from contextlib import contextmanager
from types import SimpleNamespace

from backend.app.persistence.device_security_events import DeviceSecurityEventRepository
from backend.app.persistence.devices import DeviceRepository


class RecordingConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if "FROM users" in normalized:
            row = {"id": "user-1"}
        elif "FROM devices" in normalized:
            row = {"id": "device-1", "user_id": "user-1", "status": "active"}
        elif "SELECT * FROM devices" in normalized:
            row = {
                "id": "device-1",
                "user_id": "user-1",
                "platform": "android",
                "app_version": "1.0.0",
                "display_name": "Phone",
                "public_key_fingerprint": "a" * 64,
                "status": "pending",
                "enrolled_at": "2026-01-01T00:00:00+00:00",
                "last_seen_at": None,
                "revoked_at": None,
            }
        else:
            row = None
        return SimpleNamespace(fetchone=lambda: row, fetchall=lambda: [], rowcount=1)


class RecordingDatabase:
    dialect = "postgresql"

    def __init__(self):
        self.connection = RecordingConnection()
        self.immediate_values = []

    @contextmanager
    def transaction(self, *, immediate=False):
        self.immediate_values.append(immediate)
        yield self.connection

    def connect(self):
        return self.connection


class TestableDeviceRepository(DeviceRepository):
    @staticmethod
    def _record(row):
        return row

    def get_owned(self, owner_id, device_id):
        return {"id": device_id, "user_id": owner_id}


def _index(statements, fragment):
    return next(i for i, (sql, _params) in enumerate(statements) if fragment in sql)


def test_postgres_device_enrollment_locks_active_owner_before_insert():
    database = RecordingDatabase()
    repository = TestableDeviceRepository(database)
    request = SimpleNamespace(
        platform=SimpleNamespace(value="android"),
        app_version="1.0.0",
        display_name="Phone",
        public_key_fingerprint="a" * 64,
    )

    result = repository.enroll("user-1", request)

    assert result["id"] == "device-1"
    statements = database.connection.statements
    owner_lock = _index(statements, "FROM users")
    insert = _index(statements, "INSERT INTO devices")
    assert "FOR UPDATE" in statements[owner_lock][0]
    assert owner_lock < insert
    assert database.immediate_values == [False]


def test_postgres_capability_report_locks_account_then_device_before_update():
    database = RecordingDatabase()
    repository = TestableDeviceRepository(database)
    report = SimpleNamespace(
        capabilities=[SimpleNamespace(value="microphone")],
        reported_at=SimpleNamespace(isoformat=lambda: "2026-01-01T00:00:00+00:00"),
    )

    result = repository.record_capabilities("user-1", "device-1", report)

    assert result["id"] == "device-1"
    statements = database.connection.statements
    owner_lock = _index(statements, "FROM users")
    device_lock = _index(statements, "FROM devices")
    update = _index(statements, "UPDATE devices")
    assert "FOR UPDATE" in statements[owner_lock][0]
    assert "FOR UPDATE" in statements[device_lock][0]
    assert owner_lock < device_lock < update
    assert database.immediate_values == [False]


def test_postgres_device_security_event_locks_owner_then_device_before_append():
    database = RecordingDatabase()
    repository = DeviceSecurityEventRepository(database)

    repository.record("user-1", "device-1", "device.revoked", details={"source": "user"})

    statements = database.connection.statements
    owner_lock = _index(statements, "FROM users")
    device_lock = _index(statements, "FROM devices")
    insert = _index(statements, "INSERT INTO device_security_events")
    assert "FOR UPDATE" in statements[owner_lock][0]
    assert "FOR UPDATE" in statements[device_lock][0]
    assert owner_lock < device_lock < insert
    assert database.immediate_values == [False]


class SQLiteTransactionDatabase:
    dialect = "sqlite"

    def __init__(self):
        self.immediate_values = []

    @contextmanager
    def transaction(self, *, immediate=False):
        self.immediate_values.append(immediate)
        yield


def test_sqlite_device_security_events_keep_immediate_transactions():
    database = SQLiteTransactionDatabase()
    repository = DeviceSecurityEventRepository(database)

    with repository._transaction():
        pass

    assert database.immediate_values == [True]
