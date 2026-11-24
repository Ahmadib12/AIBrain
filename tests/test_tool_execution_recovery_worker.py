import asyncio
import threading
from datetime import datetime, timezone

import pytest

from backend.app.config import Settings
from backend.app.tools.recovery import ToolExecutionRecoveryWorker


class FakeRepository:
    def __init__(self, result=0):
        self.result = result
        self.calls = []
        self.called = threading.Event()

    def recover_stale_execution_attempts(self, *, stale_before):
        self.calls.append(stale_before)
        self.called.set()
        return self.result


def test_run_once_uses_configured_stale_cutoff():
    repository = FakeRepository(result=2)
    worker = ToolExecutionRecoveryWorker(
        repository,
        interval_seconds=60,
        stale_after_seconds=300,
    )

    recovered = asyncio.run(worker.run_once())

    assert recovered == 2
    assert len(repository.calls) == 1
    cutoff = datetime.fromisoformat(repository.calls[0])
    assert cutoff.tzinfo is not None
    age = datetime.now(timezone.utc) - cutoff
    assert 299 <= age.total_seconds() <= 301


def test_worker_starts_runs_and_stops_cleanly():
    repository = FakeRepository()
    worker = ToolExecutionRecoveryWorker(
        repository,
        interval_seconds=3600,
        stale_after_seconds=300,
    )

    async def exercise():
        await worker.start()
        called = await asyncio.to_thread(repository.called.wait, 2)
        assert called, "recovery cycle did not run after startup"
        await worker.stop()
        assert worker._task is None

    asyncio.run(exercise())
    assert len(repository.calls) == 1


def test_start_is_idempotent_while_worker_is_running():
    repository = FakeRepository()
    worker = ToolExecutionRecoveryWorker(
        repository,
        interval_seconds=3600,
        stale_after_seconds=300,
    )

    async def exercise():
        await worker.start()
        first_task = worker._task
        await worker.start()
        assert worker._task is first_task
        called = await asyncio.to_thread(repository.called.wait, 2)
        assert called
        await worker.stop()

    asyncio.run(exercise())
    assert len(repository.calls) == 1


@pytest.mark.parametrize(
    "interval,stale_after",
    [(0, 300), (60, 0), (-1, 300), (60, -1)],
)
def test_worker_rejects_non_positive_intervals(interval, stale_after):
    with pytest.raises(ValueError, match="positive"):
        ToolExecutionRecoveryWorker(
            FakeRepository(),
            interval_seconds=interval,
            stale_after_seconds=stale_after,
        )


def test_recovery_settings_have_safe_positive_defaults():
    settings = Settings()
    assert settings.tool_execution_recovery_interval_seconds > 0
    assert settings.tool_execution_stale_after_seconds > 0
