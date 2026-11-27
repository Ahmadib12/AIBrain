from contextlib import contextmanager
from types import SimpleNamespace

from backend.app.persistence.identity import IdentityRepository
from backend.app.persistence.postgres.database import PostgresDatabase


class RecordingConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        if "FROM users" in sql and "SELECT id" in sql:
            row = {"id": "user-1"}
        elif "FROM devices" in sql and "SELECT id" in sql:
            row = {"id": "device-1"}
        elif "SELECT id, email, display_name, created_at" in sql:
            row = {
                "id": "user-1",
                "email": "owner@example.com",
                "display_name": "Owner",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        else:
            row = None
        return SimpleNamespace(fetchone=lambda: row, rowcount=1)

    @contextmanager
    def transaction(self):
        yield self

    def close(self):
        pass


def make_identity():
    raw = RecordingConnection()
    database = PostgresDatabase(
        "postgresql://example.invalid/aibrain",
        connect_factory=lambda *args, **kwargs: raw,
    )
    return raw, database, IdentityRepository(database, session_ttl_seconds=3600)


def test_postgres_session_creation_locks_account_and_device_before_insert():
    raw, database, identity = make_identity()
    try:
        user, token = identity.create_session(
            "user-1", device_id="device-1", auth_method="device_proof"
        )
        assert user["id"] == "user-1"
        assert token
        sql = [statement for statement, _ in raw.statements]
        assert any("FROM users" in statement and "FOR UPDATE" in statement for statement in sql)
        assert any("FROM devices" in statement and "FOR UPDATE" in statement for statement in sql)
        assert any("INSERT INTO sessions" in statement for statement in sql)
    finally:
        database.shutdown()


def test_postgres_account_erasure_locks_account_before_tombstoning():
    raw, database, identity = make_identity()
    try:
        identity.delete_user("user-1")
        sql = [statement for statement, _ in raw.statements]
        lock_index = next(
            index for index, statement in enumerate(sql)
            if "SELECT id FROM users WHERE id = %s FOR UPDATE" in statement
        )
        tombstone_index = next(
            index for index, statement in enumerate(sql)
            if "UPDATE users SET deleted_at" in statement
        )
        assert lock_index < tombstone_index
    finally:
        database.shutdown()
