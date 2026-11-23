import json
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository


def create_repository(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'confirmation.db'}")
    user_id = f"confirmation-{uuid.uuid4()}"

    database.connect().execute(
        "INSERT INTO users "
        "(id, email, password_salt, password_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            user_id,
            f"{user_id}@example.com",
            "test-salt",
            "test-hash",
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    database.connect().commit()

    return database, user_id, ToolRequestRepository(database)


def create_pending_request(repository, user_id, expires_at=None):
    return repository.create(
        user_id,
        tool_id="test-state-change",
        arguments={"value": "test"},
        status="pending",
        expires_at=expires_at,
        authorization_policy="read_only",
    )


def test_pending_request_can_be_approved_and_audited(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_pending_request(repository, user_id)

        approved = repository.approve_pending(user_id, request["id"])

        assert approved["status"] == "approved"

        row = database.connect().execute(
            "SELECT audit_json FROM tool_requests WHERE id = ?",
            (request["id"],),
        ).fetchone()
        audit = json.loads(row["audit_json"])

        assert audit["confirmation"]["confirmed_by"] == user_id
        assert audit["confirmation"]["confirmed_at"]
    finally:
        database.shutdown()


def test_another_user_cannot_approve_request(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_pending_request(repository, user_id)

        with pytest.raises(LookupError):
            repository.approve_pending("another-user", request["id"])

        assert repository.get(user_id, request["id"])["status"] == "pending"
    finally:
        database.shutdown()


def test_expired_request_cannot_be_approved(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        expired_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat()
        request = create_pending_request(repository, user_id, expired_at)

        with pytest.raises(PermissionError, match="expired"):
            repository.approve_pending(user_id, request["id"])

        assert repository.get(user_id, request["id"])["status"] == "pending"
    finally:
        database.shutdown()


def test_request_cannot_be_approved_twice(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_pending_request(repository, user_id)

        repository.approve_pending(user_id, request["id"])

        with pytest.raises(PermissionError):
            repository.approve_pending(user_id, request["id"])

        assert repository.get(user_id, request["id"])["status"] == "approved"
    finally:
        database.shutdown()


def create_approved_read_only_request(repository, user_id):
    return repository.create(
        user_id,
        tool_id="test-read-only",
        arguments={"value": "approved"},
        status="approved",
        authorization_policy="read_only",
    )


def test_execution_claim_creates_one_durable_attempt_atomically(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_approved_read_only_request(repository, user_id)

        claimed = repository.claim_for_execution(user_id, request["id"])

        assert claimed["status"] == "executing"
        assert claimed["consumed_at"] is not None

        attempt = repository.get_execution_attempt(user_id, request["id"])
        assert attempt["request_id"] == request["id"]
        assert attempt["user_id"] == user_id
        assert attempt["idempotency_key"] == request["id"]
        assert attempt["status"] == "claimed"
        assert attempt["claimed_at"]
        assert attempt["finished_at"] is None
    finally:
        database.shutdown()


def test_failed_execution_claim_rolls_back_without_attempt_record(tmp_path):
    import sqlite3

    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_approved_read_only_request(repository, user_id)
        database.connect().execute(
            """
            CREATE TRIGGER reject_test_execution_attempt
            BEFORE INSERT ON tool_execution_attempts
            BEGIN
                SELECT RAISE(ABORT, 'attempt insert rejected');
            END
            """
        )
        database.connect().commit()

        with pytest.raises(sqlite3.IntegrityError, match="attempt insert rejected"):
            repository.claim_for_execution(user_id, request["id"])

        persisted = repository.get(user_id, request["id"])
        assert persisted["status"] == "approved"
        assert persisted["consumed_at"] is None
        count = database.connect().execute(
            "SELECT COUNT(*) FROM tool_execution_attempts WHERE request_id = ?",
            (request["id"],),
        ).fetchone()[0]
        assert count == 0
    finally:
        database.shutdown()


def test_duplicate_execution_claim_does_not_create_another_attempt(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_approved_read_only_request(repository, user_id)
        repository.claim_for_execution(user_id, request["id"])

        with pytest.raises(PermissionError, match="not available"):
            repository.claim_for_execution(user_id, request["id"])

        count = database.connect().execute(
            "SELECT COUNT(*) FROM tool_execution_attempts WHERE request_id = ?",
            (request["id"],),
        ).fetchone()[0]
        assert count == 1
    finally:
        database.shutdown()


def test_completion_updates_request_and_attempt_in_one_transaction(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_approved_read_only_request(repository, user_id)
        repository.claim_for_execution(user_id, request["id"])

        completed = repository.complete_execution(
            user_id,
            request["id"],
            result={"status": "completed", "value": "done"},
        )

        assert completed["status"] == "completed"
        assert completed["result"]["value"] == "done"
        attempt = repository.get_execution_attempt(user_id, request["id"])
        assert attempt["status"] == "succeeded"
        assert attempt["finished_at"]
        assert attempt["error_code"] is None
    finally:
        database.shutdown()


def test_failure_updates_request_and_attempt(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_approved_read_only_request(repository, user_id)
        repository.claim_for_execution(user_id, request["id"])

        failed = repository.fail_execution(
            user_id,
            request["id"],
            error_code="tool_unavailable",
        )

        assert failed["status"] == "failed"
        attempt = repository.get_execution_attempt(user_id, request["id"])
        assert attempt["status"] == "failed"
        assert attempt["error_code"] == "tool_unavailable"
        assert attempt["finished_at"]
    finally:
        database.shutdown()


def test_stale_execution_recovery_marks_outcome_unknown_without_retry(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_approved_read_only_request(repository, user_id)
        repository.claim_for_execution(user_id, request["id"])

        cutoff = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        recovered = repository.recover_stale_execution_attempts(
            stale_before=cutoff
        )

        assert recovered == 1
        persisted = repository.get(user_id, request["id"])
        assert persisted["status"] == "outcome_unknown"
        assert persisted["consumed_at"] is not None

        attempt = repository.get_execution_attempt(user_id, request["id"])
        assert attempt["status"] == "outcome_unknown"
        assert attempt["error_code"] == "recovery_outcome_unknown"
        assert attempt["finished_at"]

        with pytest.raises(PermissionError, match="no longer active"):
            repository.complete_execution(
                user_id,
                request["id"],
                result={"status": "completed"},
            )
        with pytest.raises(PermissionError, match="not available"):
            repository.claim_for_execution(user_id, request["id"])

        assert repository.recover_stale_execution_attempts(
            stale_before=cutoff
        ) == 0
    finally:
        database.shutdown()


def test_stale_execution_recovery_requires_timezone_aware_cutoff(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        with pytest.raises(ValueError, match="timezone"):
            repository.recover_stale_execution_attempts(
                stale_before="2026-11-23T12:00:00"
            )
    finally:
        database.shutdown()


def test_cancelled_request_cannot_be_approved(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_pending_request(repository, user_id)
        repository.cancel_pending(user_id, request["id"])

        with pytest.raises(PermissionError):
            repository.approve_pending(user_id, request["id"])

        assert repository.get(user_id, request["id"])["status"] == "cancelled"
    finally:
        database.shutdown()


def test_concurrent_confirmations_only_approve_once(tmp_path):
    database_a, user_id, repository_a = create_repository(tmp_path)
    database_b = Database(f"sqlite:///{tmp_path / 'confirmation.db'}")
    repository_b = ToolRequestRepository(database_b)

    try:
        request = create_pending_request(repository_a, user_id)
        barrier = threading.Barrier(2)
        successes = []
        failures = []

        def confirm(repository):
            try:
                barrier.wait()
                result = repository.approve_pending(user_id, request["id"])
                successes.append(result)
            except PermissionError as error:
                failures.append(error)

        threads = [
            threading.Thread(target=confirm, args=(repository_a,)),
            threading.Thread(target=confirm, args=(repository_b,)),
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(successes) == 1
        assert len(failures) == 1
        assert repository_a.get(user_id, request["id"])["status"] == "approved"
    finally:
        database_b.shutdown()
        database_a.shutdown()


def test_tampered_request_cannot_be_confirmed(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_pending_request(repository, user_id)

        database.connect().execute(
            "UPDATE tool_requests SET arguments_json = ? WHERE id = ?",
            (json.dumps({"value": "tampered"}), request["id"]),
        )
        database.connect().commit()

        with pytest.raises(PermissionError, match="changed after proposal"):
            repository.approve_pending(user_id, request["id"])

        assert repository.get(user_id, request["id"])["status"] == "pending"
    finally:
        database.shutdown()


def test_tampered_request_cannot_be_claimed_after_confirmation(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = create_pending_request(repository, user_id)
        repository.approve_pending(user_id, request["id"])

        database.connect().execute(
            "UPDATE tool_requests SET arguments_json = ? WHERE id = ?",
            (json.dumps({"value": "tampered"}), request["id"]),
        )
        database.connect().commit()

        with pytest.raises(PermissionError, match="changed after proposal"):
            repository.claim_for_execution(user_id, request["id"])

        assert repository.get(user_id, request["id"])["status"] == "approved"
        assert repository.get(user_id, request["id"])["consumed_at"] is None
    finally:
        database.shutdown()


@pytest.mark.parametrize("authorization_policy", ["unknown", "passkey"])
def test_non_read_only_request_cannot_use_generic_approval(
    tmp_path,
    authorization_policy,
):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = repository.create(
            user_id,
            tool_id="test-state-change",
            arguments={"value": "test"},
            status="pending",
            authorization_policy=authorization_policy,
        )

        with pytest.raises(
            PermissionError,
            match="Generic approval is restricted to read-only requests",
        ):
            repository.approve_pending(user_id, request["id"])

        stored = repository.get(user_id, request["id"])
        assert stored["status"] == "pending"
        assert stored["consumed_at"] is None
        assert stored["authorization_policy"] == authorization_policy
    finally:
        database.shutdown()


@pytest.mark.parametrize("authorization_policy", ["unknown", "passkey"])
def test_non_read_only_request_cannot_use_generic_execution(
    tmp_path,
    authorization_policy,
):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = repository.create(
            user_id,
            tool_id="test-state-change",
            arguments={"value": "test"},
            status="approved",
            authorization_policy=authorization_policy,
        )

        with pytest.raises(
            PermissionError,
            match="Generic execution is restricted to read-only requests",
        ):
            repository.claim_for_execution(user_id, request["id"])

        stored = repository.get(user_id, request["id"])
        assert stored["status"] == "approved"
        assert stored["consumed_at"] is None
        assert stored["authorization_policy"] == authorization_policy
    finally:
        database.shutdown()


def test_manually_approved_passkey_request_cannot_be_claimed_generically(
    tmp_path,
):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = repository.create(
            user_id,
            tool_id="test-state-change",
            arguments={"value": "test"},
            status="pending",
            authorization_policy="passkey",
        )

        connection = database.connect()
        connection.execute(
            "UPDATE tool_requests SET status = 'approved' WHERE id = ?",
            (request["id"],),
        )
        connection.commit()

        with pytest.raises(
            PermissionError,
            match="Generic execution is restricted to read-only requests",
        ):
            repository.claim_for_execution(user_id, request["id"])

        stored = repository.get(user_id, request["id"])
        assert stored["status"] == "approved"
        assert stored["consumed_at"] is None
        assert stored["authorization_policy"] == "passkey"
    finally:
        database.shutdown()



def test_cancelled_approved_request_cannot_be_claimed(tmp_path):
    database, user_id, repository = create_repository(tmp_path)
    try:
        request = repository.create(
            user_id,
            tool_id="state-change-test",
            arguments={"value": "approved"},
            status="approved",
            expires_at=(
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(),
            contract_fingerprint="a" * 64,
            authorization_policy="passkey",
        )

        cancelled = repository.cancel_pending(user_id, request["id"])

        assert cancelled["status"] == "cancelled"
        assert cancelled["consumed_at"] is None
        with pytest.raises(PermissionError, match="not available"):
            repository.claim_passkey_authorized_for_execution(
                user_id,
                request["id"],
                expected_contract_fingerprint="a" * 64,
            )
    finally:
        database.shutdown()
