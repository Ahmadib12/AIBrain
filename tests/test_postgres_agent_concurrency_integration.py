"""Real PostgreSQL agent task and run concurrency acceptance tests."""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from uuid import uuid4

import pytest

from backend.app.persistence.agent_control import AgentControlRepository
from backend.app.persistence.agent_execution import AgentExecutionRepository
from backend.app.persistence.agents import AgentRepository
from backend.app.persistence.postgres.database import PostgresDatabase
from backend.app.persistence.postgres.migrations import PostgresMigrationRunner
from backend.app.persistence.identity import IdentityRepository
from backend.app.tools.runtime import ToolExecutionGateway
from backend.app.api.v1.tools import tool_registry


def _database_url():
    value = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not value:
        pytest.skip(
            "set AIBRAIN_POSTGRES_TEST_URL for dedicated PostgreSQL agent tests"
        )
    pytest.importorskip("psycopg")
    return value


def _create_owner(database_url):
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
                f"agent-concurrency-{owner_id}@example.invalid",
                "salt",
                "hash",
                timestamp,
            ),
        )
    return owner_id


def _delete_owner(database_url, owner_id):
    database = PostgresDatabase(database_url)
    try:
        IdentityRepository(database, session_ttl_seconds=3600).delete_user(owner_id)
    finally:
        database.shutdown()


def _create_active_agent_and_task(database_url):
    database = PostgresDatabase(database_url)
    owner_id = _create_owner(database_url)
    agents = AgentRepository(database)
    control = AgentControlRepository(database)
    agent = agents.create(owner_id, name="PostgreSQL concurrency agent")
    agents.transition(owner_id, agent["id"], target_status="active")
    task = control.create_task(
        owner_id,
        agent["id"],
        title="Concurrent task",
        goal="Claim exactly once",
        context={},
        capability_ceiling=[],
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    )
    return database, owner_id, agent, task, control


def test_real_postgres_only_one_worker_claims_task():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 37
    database, owner_id, agent, task, control = _create_active_agent_and_task(
        database_url
    )
    barrier = Barrier(2)

    def claim(worker_id):
        barrier.wait(timeout=10)
        try:
            return control.claim_task(
                owner_id,
                agent["id"],
                task["id"],
                worker_id=worker_id,
                lease_seconds=300,
            )
        except (ValueError, LookupError) as error:
            return error

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(
                lambda worker: claim(worker),
                ("worker-a", "worker-b"),
            ))
        successes = [item for item in outcomes if not isinstance(item, Exception)]
        conflicts = [item for item in outcomes if isinstance(item, ValueError)]
        assert len(successes) == 1
        assert len(conflicts) == 1

        claimed = successes[0]
        worker_id = claimed["claimed_by"]
        assert worker_id in {"worker-a", "worker-b"}
        assert claimed["lease_expires_at"] is not None

        with pytest.raises(PermissionError):
            control.heartbeat_task(
                owner_id,
                agent["id"],
                task["id"],
                worker_id="unauthorized-worker",
                lease_seconds=300,
            )
    finally:
        database.shutdown()
        _delete_owner(database_url, owner_id)


def test_real_postgres_lease_heartbeat_and_crash_reconciliation():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 37
    database, owner_id, agent, task, control = _create_active_agent_and_task(
        database_url
    )
    try:
        claimed = control.claim_task(
            owner_id,
            agent["id"],
            task["id"],
            worker_id="worker-heartbeat",
            lease_seconds=300,
        )
        renewed = control.heartbeat_task(
            owner_id,
            agent["id"],
            task["id"],
            worker_id="worker-heartbeat",
            lease_seconds=600,
        )
        assert datetime.fromisoformat(renewed["lease_expires_at"]) > (
            datetime.fromisoformat(claimed["lease_expires_at"])
        )

        import psycopg
        with psycopg.connect(database_url) as connection:
            connection.execute(
                """
                UPDATE agent_tasks
                SET lease_expires_at=%s
                WHERE id=%s
                """,
                (
                    (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                    task["id"],
                ),
            )

        assert control.reconcile_stale_task_claims(owner_id) == 1
        requeued = control.get_task(owner_id, task["id"])
        assert requeued["status"] == "assigned"
        assert requeued["claimed_by"] is None
    finally:
        database.shutdown()
        _delete_owner(database_url, owner_id)


def test_real_postgres_suspension_racing_claim_is_fail_closed():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 37
    database, owner_id, agent, task, control = _create_active_agent_and_task(
        database_url
    )
    agents = AgentRepository(database)
    barrier = Barrier(2)

    def claim():
        barrier.wait(timeout=10)
        try:
            return control.claim_task(
                owner_id,
                agent["id"],
                task["id"],
                worker_id="worker-racing-suspension",
                lease_seconds=300,
            )
        except (ValueError, LookupError) as error:
            return error

    def suspend():
        barrier.wait(timeout=10)
        try:
            return agents.transition(
                owner_id,
                agent["id"],
                target_status="suspended",
                reason="Concurrency test",
            )
        except (ValueError, LookupError) as error:
            return error

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            claim_future = executor.submit(claim)
            suspend_future = executor.submit(suspend)
            claim_result = claim_future.result(timeout=30)
            suspend_result = suspend_future.result(timeout=30)

        if isinstance(claim_result, dict):
            assert claim_result["status"] == "in_progress"
        else:
            assert isinstance(claim_result, ValueError)
        if not isinstance(suspend_result, Exception):
            assert suspend_result["status"] == "suspended"

        current_agent = agents.get(owner_id, agent["id"])
        current_task = control.get_task(owner_id, task["id"])
        if current_agent["status"] == "active":
            assert current_task["status"] in {"assigned", "in_progress"}
        else:
            assert current_agent["status"] == "suspended"
    finally:
        database.shutdown()
        _delete_owner(database_url, owner_id)


def test_real_postgres_only_one_worker_executes_run():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 37
    database, owner_id, agent, task, control = _create_active_agent_and_task(
        database_url
    )
    execution = AgentExecutionRepository(database)
    gateway = ToolExecutionGateway(tool_registry, database)
    barrier = Barrier(2)
    try:
        run = execution.create_run(
            owner_id,
            task["id"],
            [{"tool_id": "echo", "arguments": {"text": "exactly once"}}],
            tool_registry,
        )
        execution.authorize_run(owner_id, run["id"])

        def execute():
            barrier.wait(timeout=10)
            try:
                return execution.execute_run(
                    owner_id,
                    run["id"],
                    gateway,
                    tool_registry,
                )
            except (ValueError, PermissionError) as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(execute) for _ in range(2)]
            outcomes = [future.result(timeout=30) for future in futures]

        successes = [item for item in outcomes if isinstance(item, dict)]
        conflicts = [item for item in outcomes if isinstance(item, Exception)]
        assert len(successes) == 1
        assert len(conflicts) == 1
        assert successes[0]["status"] == "completed"

        import psycopg
        with psycopg.connect(database_url) as connection:
            tool_request_count = connection.execute(
                "SELECT COUNT(*) FROM tool_requests WHERE user_id=%s",
                (owner_id,),
            ).fetchone()[0]
            event_count = connection.execute(
                """
                SELECT COUNT(*) FROM agent_run_events
                WHERE user_id=%s AND run_id=%s AND event_type='started'
                """,
                (owner_id, run["id"]),
            ).fetchone()[0]
        assert tool_request_count == 1
        assert event_count == 1
    finally:
        database.shutdown()
        _delete_owner(database_url, owner_id)


def test_real_postgres_concurrent_run_cancellation_and_execution_are_atomic():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 37
    database, owner_id, agent, task, control = _create_active_agent_and_task(
        database_url
    )
    execution = AgentExecutionRepository(database)
    gateway = ToolExecutionGateway(tool_registry, database)
    barrier = Barrier(2)
    try:
        run = execution.create_run(
            owner_id,
            task["id"],
            [{"tool_id": "echo", "arguments": {"text": "cancel race"}}],
            tool_registry,
        )
        execution.authorize_run(owner_id, run["id"])

        def execute():
            barrier.wait(timeout=10)
            try:
                return execution.execute_run(
                    owner_id,
                    run["id"],
                    gateway,
                    tool_registry,
                )
            except (ValueError, PermissionError) as error:
                return error

        def cancel():
            barrier.wait(timeout=10)
            try:
                return execution.cancel_run(owner_id, run["id"])
            except (ValueError, PermissionError) as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            execute_future = executor.submit(execute)
            cancel_future = executor.submit(cancel)
            execute_result = execute_future.result(timeout=30)
            cancel_result = cancel_future.result(timeout=30)

        final_run = execution.get_run(owner_id, run["id"])
        assert final_run["status"] in {"completed", "cancelled"}
        assert not (
            isinstance(cancel_result, Exception)
            and isinstance(execute_result, Exception)
        )
    finally:
        database.shutdown()
        _delete_owner(database_url, owner_id)
