from types import SimpleNamespace
import sqlite3

from backend.app.api.v1.devices import _is_device_fingerprint_conflict


class PostgresError(Exception):
    def __init__(self, sqlstate, constraint_name):
        super().__init__("database constraint violation")
        self.sqlstate = sqlstate
        self.diag = SimpleNamespace(constraint_name=constraint_name)


def test_sqlite_device_fingerprint_unique_violation_is_recognized():
    error = sqlite3.IntegrityError(
        "UNIQUE constraint failed: devices.user_id, devices.public_key_fingerprint"
    )

    assert _is_device_fingerprint_conflict(error)


def test_postgres_device_fingerprint_unique_violation_is_recognized():
    error = PostgresError(
        "23505", "devices_user_id_public_key_fingerprint_key"
    )

    assert _is_device_fingerprint_conflict(error)


def test_postgres_unrelated_unique_constraint_is_not_mapped_to_device_conflict():
    error = PostgresError("23505", "devices_pkey")

    assert not _is_device_fingerprint_conflict(error)


def test_non_unique_postgres_error_is_not_mapped_to_device_conflict():
    error = PostgresError("23514", "devices_user_id_public_key_fingerprint_key")

    assert not _is_device_fingerprint_conflict(error)


def test_unrelated_sqlite_integrity_error_is_not_mapped_to_device_conflict():
    error = sqlite3.IntegrityError("FOREIGN KEY constraint failed")

    assert not _is_device_fingerprint_conflict(error)
