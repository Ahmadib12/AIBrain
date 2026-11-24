import asyncio
import logging

from backend.app.persistence.memory import MemoryRepository


class MemoryRetentionWorker:
    """Periodically removes expired memory records from persistent storage."""

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

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        while True:
            try:
                self.repository.purge_expired()
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.getLogger("aibrain.memory").warning(
                    "Memory retention cleanup failed"
                )
            await asyncio.sleep(self.interval_seconds)

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
