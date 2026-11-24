import asyncio
import logging

from backend.app.persistence.memory import MemoryRepository


class MemoryRetentionWorker:
    """Periodically purges expired memory and waits for in-flight work at shutdown."""

    def __init__(
        self,
        repository: MemoryRepository,
        *,
        interval_seconds: int = 3_600,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("Memory retention interval must be positive")
        self.repository = repository
        self.interval_seconds = interval_seconds
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._task = asyncio.create_task(self._run(stop_event))

    async def _run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                # The worker owns this awaitable and shutdown waits for it.
                # Do not cancel the task while SQLite work is still running.
                await asyncio.to_thread(self.repository.purge_expired)
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.getLogger("aibrain.memory").warning(
                    "Memory retention cleanup failed"
                )
            if stop_event.is_set():
                break
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self.interval_seconds,
                )
            except asyncio.TimeoutError:
                continue

    async def stop(self) -> None:
        task = self._task
        stop_event = self._stop_event
        self._task = None
        self._stop_event = None
        if task is None:
            return
        if stop_event is not None:
            stop_event.set()
        # Waiting instead of cancelling prevents a worker thread from touching
        # the database after application lifespan closes the connections.
        await task
