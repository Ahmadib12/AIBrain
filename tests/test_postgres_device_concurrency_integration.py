"""Real PostgreSQL device lifecycle concurrency acceptance tests.

Set AIBRAIN_POSTGRES_TEST_URL to a dedicated PostgreSQL test database.
"""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
from uuid import uuid4

import pytest

from backend.app.devices.contracts import (
    DeviceCapability,
    DeviceCapabilityReport,
    DeviceRegistrationRequest,
)
from backend.app.persistence.devices import DeviceRepository
from backend.app.persistence.postgres.database import PostgresDatabase
from backend.app.persistence.postgres.migrations import PostgresMigrationRunner
from backend.app.persistence.identity import IdentityRepository


def _database_url():
    value = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not value:
        pytest.skip(
            "set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database"
        )
    pytest.importorskip("psycopg")
    return value


def _create_owner(database_url: str, suffix: str) -> str:
    import psycopg

    owner_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            INSERT INTO users (
                id, email, password_salt, password_hash, created_at
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            (
                owner_id,
                f"device-concurrency-{suffix}@example.invalid",
                "salt",
                "hash",
                timestamp,
            ),
        )
    return owner_id


def _delete_owner(database_url: str, owner_id: str) -> None:
    database = PostgresDatabase(database_url)
    try:
        IdentityRepository(database, session_ttl_seconds=3600).delete_user(owner_id)
    finally:
        database.shutdown()


def test_real_postgres_concurrent_duplicate_enrollment_is_serialized():
    database_url = _database_url()
    import psycopg
    assert PostgresMigrationRunner(database_url).migrate() == 38
    owner_id = _create_owner(database_url, uuid4().hex)
    database = PostgresDatabase(database_url)
    barrier = Barrier(2)
    request = DeviceRegistrationRequest(
        platform="android",
        app_version="1.0.0",
        display_name="Concurrency test phone",
        public_key_fingerprint="a" * 64,
    )

    def enroll():
        barrier.wait(timeout=10)
        return DeviceRepository(database).enroll(owner_id, request)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(enroll) for _ in range(2)]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=30))
                except psycopg.errors.UniqueViolation as error:
                    outcomes.append(error)

        successes = [item for item in outcomes if not isinstance(item, Exception)]
        conflicts = [item for item in outcomes if isinstance(item, psycopg.errors.UniqueViolation)]
        assert len(successes) == 1
        assert len(conflicts) == 1
        assert conflicts[0].diag.constraint_name == (
            "devices_user_id_public_key_fingerprint_key"
        )

        with psycopg.connect(database_url) as connection:
            rows = connection.execute(
                """
                SELECT id, status FROM devices
                WHERE user_id=%s AND public_key_fingerprint=%s
                """,
                (owner_id, "a" * 64),
            ).fetchall()
        assert len(rows) == 1
        assert rows[0][1] == "pending"
    finally:
        database.shutdown()
        _delete_owner(database_url, owner_id)


def test_real_postgres_concurrent_capability_report_and_revoke_never_resurrect_device():
    database_url = _database_url()
    import psycopg
    assert PostgresMigrationRunner(database_url).migrate() == 38
    owner_id = _create_owner(database_url, uuid4().hex)
    device_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    fingerprint = "b" * 64
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            INSERT INTO devices (
                id, user_id, platform, app_version, display_name,
                public_key_fingerprint, status, enrolled_at, public_key_b64
            ) VALUES (%s, %s, 'android', '1.0.0', 'Concurrency test phone',
                      %s, 'active', %s, %s)
            """,
            (device_id, owner_id, fingerprint, timestamp, "cHVibGljLWtleQ=="),
        )

    database = PostgresDatabase(database_url)
    barrier = Barrier(2)
    report = DeviceCapabilityReport(
        capabilities=(DeviceCapability.MICROPHONE,),
        reported_at=datetime.now(timezone.utc),
    )

    def record_capabilities():
        barrier.wait(timeout=10)
        try:
            return DeviceRepository(database).record_capabilities(
                owner_id, device_id, report
            )
        except PermissionError as error:
            return error

    def revoke():
        barrier.wait(timeout=10)
        return DeviceRepository(database).revoke(owner_id, device_id)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            report_future = executor.submit(record_capabilities)
            revoke_future = executor.submit(revoke)
            report_result = report_future.result(timeout=30)
            revoke_result = revoke_future.result(timeout=30)

        assert revoke_result.status == "revoked"
        if isinstance(report_result, PermissionError):
            assert str(report_result) == (
                "Only active devices may report capabilities"
            )
        else:
            assert str(report_result.device_id) == device_id
        with psycopg.connect(database_url) as connection:
            row = connection.execute(
                "SELECT status, revoked_at FROM devices WHERE id=%s AND user_id=%s",
                (device_id, owner_id),
            ).fetchone()
        assert row[0] == "revoked"
        assert row[1] is not None
    finally:
        database.shutdown()
        _delete_owner(database_url, owner_id)
