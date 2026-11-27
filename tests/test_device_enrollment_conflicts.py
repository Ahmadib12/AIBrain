import asyncio
import sqlite3
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from backend.app.api.v1 import devices as devices_api
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


@pytest.mark.parametrize(
    "error",
    [
        sqlite3.IntegrityError(
            "UNIQUE constraint failed: "
            "devices.user_id, devices.public_key_fingerprint"
        ),
        PostgresError(
            "23505", "devices_user_id_public_key_fingerprint_key"
        ),
    ],
)
def test_enrollment_endpoint_maps_supported_fingerprint_conflicts(
    error, monkeypatch
):
    class FailingDeviceRepository:
        def enroll(self, owner_id, request):
            raise error

    monkeypatch.setattr(
        devices_api,
        "get_app_state",
        lambda: SimpleNamespace(devices=FailingDeviceRepository()),
    )

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            devices_api.enroll_device(SimpleNamespace(), {"id": "user-1"})
        )

    assert raised.value.status_code == 409
    assert raised.value.detail["code"] == "DEVICE_ALREADY_ENROLLED"


def test_enrollment_endpoint_does_not_hide_unrelated_database_errors(monkeypatch):
    failure = PostgresError("23505", "devices_pkey")

    class FailingDeviceRepository:
        def enroll(self, owner_id, request):
            raise failure

    monkeypatch.setattr(
        devices_api,
        "get_app_state",
        lambda: SimpleNamespace(devices=FailingDeviceRepository()),
    )

    with pytest.raises(PostgresError):
        asyncio.run(
            devices_api.enroll_device(SimpleNamespace(), {"id": "user-1"})
        )
