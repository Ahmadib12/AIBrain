import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository


def create_repositories(tmp_path):
    database_path = tmp_path / "execution-concurrency.db"
    database_url = f"sqlite:///{database_path}"
    database_a = Database(database_url)
    database_b = Database(database_url)
    user_id = f"concurrency-{uuid.uuid4()}"

    database_a.connect().execute(
        """
        INSERT INTO users
            (id, email, password_salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user_id,
            f"{user_id}@example.com",
            "test-salt",
            "test-hash",
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    database_a.connect().commit()

    return (
        database_a,
        database_b,
        user_id,
        ToolRequestRepository(database_a),
        ToolRequestRepository(database_b),
    )


def create_unknown_attempt(repository, user_id):
    request = repository.create(
        user_id,
        tool_id="concurrency-test",
        arguments={"operation": "verify external state"},
        status="approved",
        authorization_policy="read_only",
    )
    repository.claim_for_execution(user_id, request["id"])
    stale_before = (
        datetime.now(timezone.utc) + timedelta(minutes=1)
    ).isoformat()
    assert repository.recover_stale_execution_attempts(
        stale_before=stale_before
    ) == 1
    return request


def assert_request_and_attempt_match(repository, user_id, request_id):
    request = repository.get(user_id, request_id)
    attempt = repository.get_execution_attempt(user_id, request_id)

    expected_attempt_status = {
        "completed": "succeeded",
        "failed": "failed",
        "outcome_unknown": "outcome_unknown",
    }[request["status"]]
    assert attempt["status"] == expected_attempt_status
    return request, attempt


def test_concurrent_reconciliation_allows_exactly_one_terminal_transition(
    tmp_path,
):
    database_a, database_b, user_id, repository_a, repository_b = (
        create_repositories(tmp_path)
    )
    try:
        request = create_unknown_attempt(repository_a, user_id)
        barrier = threading.Barrier(2)

        def reconcile(repository, outcome):
            barrier.wait(timeout=5)
            try:
                if outcome == "succeeded":
                    repository.reconcile_execution_attempt(
                        user_id,
                        request["id"],
                        outcome="succeeded",
                        note="External operation independently verified.",
                        result={"verified": True},
                    )
                else:
                    repository.reconcile_execution_attempt(
                        user_id,
                        request["id"],
                        outcome="failed",
                        note="External operation independently verified absent.",
                        error_code="external_not_applied",
                    )
                return "reconciled"
            except PermissionError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                (
                    executor.submit(reconcile, repository_a, "succeeded"),
                    executor.submit(reconcile, repository_b, "failed"),
                )
            )
            results = [future.result(timeout=10) for future in outcomes]

        assert sorted(results) == ["reconciled", "rejected"]
        persisted, attempt = assert_request_and_attempt_match(
            repository_a, user_id, request["id"]
        )
        assert persisted["status"] in ("completed", "failed")
        assert attempt["finished_at"]

        row = database_a.connect().execute(
            "SELECT audit_json FROM tool_requests WHERE id = ? AND user_id = ?",
            (request["id"], user_id),
        ).fetchone()
        audit = json.loads(row["audit_json"])
        assert audit["execution_reconciliation"]["outcome"] in (
            "succeeded",
            "failed",
        )
        assert audit["execution_reconciliation"]["reconciled_by"] == user_id
        assert set(audit) == {"proposal", "execution_reconciliation"}
    finally:
        database_b.shutdown()
        database_a.shutdown()


def test_concurrent_recovery_workers_transition_attempt_only_once(tmp_path):
    database_a, database_b, user_id, repository_a, repository_b = (
        create_repositories(tmp_path)
    )
    try:
        request = repository_a.create(
            user_id,
            tool_id="concurrent-recovery-test",
            arguments={"operation": "recover stale claim"},
            status="approved",
            authorization_policy="read_only",
        )
        repository_a.claim_for_execution(user_id, request["id"])
        stale_before = (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat()
        barrier = threading.Barrier(2)

        def recover(repository):
            barrier.wait(timeout=5)
            return repository.recover_stale_execution_attempts(
                stale_before=stale_before
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(recover, repository_a),
                executor.submit(recover, repository_b),
            ]
            recovered_counts = [future.result(timeout=10) for future in futures]

        assert sum(recovered_counts) == 1
        persisted, attempt = assert_request_and_attempt_match(
            repository_a, user_id, request["id"]
        )
        assert persisted["status"] == "outcome_unknown"
        assert attempt["status"] == "outcome_unknown"
        assert attempt["error_code"] == "recovery_outcome_unknown"
        assert attempt["finished_at"]
    finally:
        database_b.shutdown()
        database_a.shutdown()


def test_recovery_racing_with_reconciliation_never_leaves_partial_state(
    tmp_path,
):
    database_a, database_b, user_id, repository_a, repository_b = (
        create_repositories(tmp_path)
    )
    try:
        request = repository_a.create(
            user_id,
            tool_id="recovery-reconciliation-race",
            arguments={"operation": "resolve uncertain claim"},
            status="approved",
            authorization_policy="read_only",
        )
        repository_a.claim_for_execution(user_id, request["id"])
        stale_before = (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat()
        barrier = threading.Barrier(2)

        def recover():
            barrier.wait(timeout=5)
            return repository_a.recover_stale_execution_attempts(
                stale_before=stale_before
            )

        def reconcile():
            barrier.wait(timeout=5)
            try:
                repository_b.reconcile_execution_attempt(
                    user_id,
                    request["id"],
                    outcome="succeeded",
                    note="External operation independently verified.",
                    result={"verified": True},
                )
                return "reconciled"
            except PermissionError:
                # Reconciliation may run before recovery has exposed an
                # outcome_unknown state. That is a safe refusal, not a retry.
                return "not_yet_reconcilable"

        with ThreadPoolExecutor(max_workers=2) as executor:
            recovery_future = executor.submit(recover)
            reconciliation_future = executor.submit(reconcile)
            recovered = recovery_future.result(timeout=10)
            reconciliation_result = reconciliation_future.result(timeout=10)

        assert recovered in (0, 1)
        assert reconciliation_result in (
            "reconciled",
            "not_yet_reconcilable",
        )
        persisted, attempt = assert_request_and_attempt_match(
            repository_a, user_id, request["id"]
        )

        if reconciliation_result == "reconciled":
            assert recovered == 1
            assert persisted["status"] == "completed"
            assert attempt["status"] == "succeeded"
            row = database_a.connect().execute(
                "SELECT audit_json FROM tool_requests WHERE id = ?",
                (request["id"],),
            ).fetchone()
            assert "execution_reconciliation" in json.loads(row["audit_json"])
        else:
            assert recovered == 1
            assert persisted["status"] == "outcome_unknown"
            assert attempt["status"] == "outcome_unknown"
    finally:
        database_b.shutdown()
        database_a.shutdown()


def test_reconciliation_rolls_back_request_and_audit_if_attempt_update_fails(
    tmp_path,
):
    import sqlite3

    database_a, database_b, user_id, repository_a, _ = create_repositories(
        tmp_path
    )
    try:
        request = create_unknown_attempt(repository_a, user_id)
        database_a.connect().execute(
            """
            CREATE TRIGGER reject_reconciliation_attempt_update
            BEFORE UPDATE ON tool_execution_attempts
            WHEN NEW.request_id = OLD.request_id
            BEGIN
                SELECT RAISE(ABORT, 'attempt update rejected');
            END
            """
        )
        database_a.connect().commit()

        with pytest.raises(
            sqlite3.IntegrityError,
            match="attempt update rejected",
        ):
            repository_a.reconcile_execution_attempt(
                user_id,
                request["id"],
                outcome="succeeded",
                note="External operation independently verified.",
                result={"verified": True},
            )

        persisted = repository_a.get(user_id, request["id"])
        attempt = repository_a.get_execution_attempt(user_id, request["id"])
        assert persisted["status"] == "outcome_unknown"
        assert attempt["status"] == "outcome_unknown"

        row = database_a.connect().execute(
            "SELECT audit_json FROM tool_requests WHERE id = ?",
            (request["id"],),
        ).fetchone()
        audit = json.loads(row["audit_json"])
        assert "execution_reconciliation" not in audit
    finally:
        database_b.shutdown()
        database_a.shutdown()



def test_recovery_rolls_back_attempt_if_request_transition_fails(tmp_path):
    import sqlite3

    database_a, database_b, user_id, repository_a, _ = create_repositories(
        tmp_path
    )
    try:
        request = repository_a.create(
            user_id,
            tool_id="recovery-rollback-test",
            arguments={"operation": "recover stale claim"},
            status="approved",
            authorization_policy="read_only",
        )
        repository_a.claim_for_execution(user_id, request["id"])
        database_a.connect().execute(
            """
            CREATE TRIGGER reject_recovery_request_update
            BEFORE UPDATE ON tool_requests
            WHEN NEW.id = OLD.id AND NEW.status = 'outcome_unknown'
            BEGIN
                SELECT RAISE(ABORT, 'request update rejected');
            END
            """
        )
        database_a.connect().commit()

        stale_before = (
            datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat()
        with pytest.raises(
            sqlite3.IntegrityError,
            match="request update rejected",
        ):
            repository_a.recover_stale_execution_attempts(
                stale_before=stale_before
            )

        persisted = repository_a.get(user_id, request["id"])
        attempt = repository_a.get_execution_attempt(user_id, request["id"])
        assert persisted["status"] == "executing"
        assert attempt["status"] == "claimed"
        assert attempt["finished_at"] is None
    finally:
        database_b.shutdown()
        database_a.shutdown()
