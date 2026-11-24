import asyncio
import threading

import pytest

from backend.app.persistence.memory_retention import MemoryRetentionWorker


class RecordingMemoryRepository:
    def __init__(self) -> None:
        self.calls = 0
        self.loop = None
        self.completed = None

    def purge_expired(self) -> int:
        self.calls += 1
        if self.loop is not None and self.completed is not None:
            self.loop.call_soon_threadsafe(self.completed.set)
        return 0


@pytest.mark.asyncio
async def test_retention_worker_runs_cleanup_and_stops_cleanly():
    repository = RecordingMemoryRepository()
    repository.loop = asyncio.get_running_loop()
    repository.completed = asyncio.Event()
    worker = MemoryRetentionWorker(repository, interval_seconds=3600)

    await worker.start()
    await asyncio.wait_for(repository.completed.wait(), timeout=2)
    await worker.stop()

    assert repository.calls >= 1
    assert worker._task is None


@pytest.mark.asyncio
async def test_retention_worker_start_is_idempotent_and_stop_is_safe():
    repository = RecordingMemoryRepository()
    worker = MemoryRetentionWorker(repository, interval_seconds=3600)

    await worker.start()
    task = worker._task
    await worker.start()
    assert worker._task is task
    await worker.stop()
    await worker.stop()


def test_retention_worker_rejects_nonpositive_interval():
    with pytest.raises(ValueError, match="positive"):
        MemoryRetentionWorker(RecordingMemoryRepository(), interval_seconds=0)


@pytest.mark.asyncio
async def test_retention_worker_waits_for_inflight_cleanup_before_stop():
    started = threading.Event()
    release = threading.Event()

    class BlockingRepository:
        def purge_expired(self) -> int:
            started.set()
            release.wait(timeout=3)
            return 0

    worker = MemoryRetentionWorker(BlockingRepository(), interval_seconds=3600)
    await worker.start()
    assert await asyncio.to_thread(started.wait, 2)

    stop_task = asyncio.create_task(worker.stop())
    await asyncio.sleep(0)
    assert not stop_task.done()

    release.set()
    await asyncio.wait_for(stop_task, timeout=2)
    assert worker._task is None

