"""True multi-process tests for durable security-notification claims.

These tests use separate OS processes and independent SQLite connections. The
minimal schema mirrors the outbox columns consumed by SecurityNotificationOutbox
so the tests isolate claim/lease coordination from application startup.
"""
from contextlib import contextmanager
import multiprocessing
import sqlite3
from pathlib import Path

from backend.app.persistence.security_notifications import SecurityNotificationOutbox


class _ProcessSQLiteDatabase:
    """Small process-local adapter exposing the Database interface the repo uses."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._local = __import__("threading").local()

    def connect(self):
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.path, timeout=10)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA journal_mode = WAL")
            self._local.connection = connection
        return connection

    @contextmanager
    def transaction(self, *, immediate: bool = False):
        connection = self.connect()
        connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()


def _initialize_outbox(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE security_notification_outbox (
                id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                available_at TEXT NOT NULL,
                claimed_at TEXT,
                claim_token TEXT,
                delivered_at TEXT,
                failed_at TEXT,
                failure_code TEXT,
                redrive_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            INSERT INTO security_notification_outbox (
                id, event_id, user_id, recipient_email, notification_type,
                payload_json, status, attempts, created_at, available_at
            ) VALUES (
                'notification-1', 'event-1', 'user-1', 'owner@example.test',
                'device.recovery.completed', '{"device_id":"device-1"}',
                'pending', 0, '2026-01-01T00:00:00+00:00',
                '2000-01-01T00:00:00+00:00'
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def _claim_in_process(database_path: str, start_event, result_queue) -> None:
    try:
        start_event.wait(timeout=10)
        repository = SecurityNotificationOutbox(
            _ProcessSQLiteDatabase(database_path)
        )
        claimed = repository.claim_batch(limit=1, lease_seconds=300)
        result_queue.put(
            [
                {
                    "id": item["id"],
                    "attempts": item["attempts"],
                    "claim_token": item["claim_token"],
                }
                for item in claimed
            ]
        )
    except BaseException as exc:
        result_queue.put({"error": repr(exc)})


def _run_claim_processes(database_path: Path, count: int = 2):
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_claim_in_process,
            args=(str(database_path), start_event, result_queue),
        )
        for _ in range(count)
    ]
    for process in processes:
        process.start()
    start_event.set()

    results = []
    for _ in processes:
        results.append(result_queue.get(timeout=20))
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
    result_queue.close()
    result_queue.join_thread()
    errors = [result for result in results if isinstance(result, dict)]
    assert errors == []
    return results


def test_independent_processes_cannot_claim_the_same_notification(tmp_path):
    database_path = tmp_path / "notification-outbox.sqlite3"
    _initialize_outbox(database_path)

    results = _run_claim_processes(database_path, count=2)
    claimed = [item for batch in results for item in batch]

    assert len(claimed) == 1
    assert claimed[0]["id"] == "notification-1"
    assert claimed[0]["attempts"] == 1

    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute(
            "SELECT status, attempts FROM security_notification_outbox "
            "WHERE id='notification-1'"
        ).fetchone()
    finally:
        connection.close()
    assert row == ("processing", 1)


def test_notification_claim_recovers_after_claiming_process_exits(tmp_path):
    database_path = tmp_path / "notification-crash-recovery.sqlite3"
    _initialize_outbox(database_path)

    first_results = _run_claim_processes(database_path, count=1)
    first_claim = first_results[0][0]
    assert first_claim["id"] == "notification-1"
    assert first_claim["attempts"] == 1

    # The first worker process has exited without acknowledging delivery.
    # Move its lease into the past to model expiry after a real process crash.
    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            "UPDATE security_notification_outbox "
            "SET claimed_at='2000-01-01T00:00:00+00:00' "
            "WHERE id='notification-1'"
        )
        connection.commit()
    finally:
        connection.close()

    second_results = _run_claim_processes(database_path, count=1)
    recovered = second_results[0][0]

    assert recovered["id"] == "notification-1"
    assert recovered["attempts"] == 2
    assert recovered["claim_token"] != first_claim["claim_token"]
