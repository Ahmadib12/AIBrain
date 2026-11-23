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
        assert cancelled["consumed_at"] is not None
        with pytest.raises(PermissionError, match="not available"):
            repository.claim_passkey_authorized_for_execution(
                user_id,
                request["id"],
                expected_contract_fingerprint="a" * 64,
            )
    finally:
        database.shutdown()
