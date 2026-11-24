"""Periodic expiry reconciliation for owner integration connections."""
import asyncio
import logging

from backend.app.persistence.integration_connections import IntegrationConnectionRepository


class IntegrationConnectionExpiryWorker:
    def __init__(
        self, repository: IntegrationConnectionRepository, *,
        interval_seconds: int = 60,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("Integration expiry interval must be positive")
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
                await asyncio.to_thread(self.repository.expire_due)
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.getLogger("aibrain.integrations").warning(
                    "Integration expiry reconciliation failed"
                )
            if stop_event.is_set():
                break
            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=self.interval_seconds
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
        await task
