"""Recovery worker for abandoned durable integration dispatches.

This worker only classifies stale in-flight dispatches as outcome-unknown. It
never replays an adapter call or attempts to infer the remote provider outcome.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone


logger = logging.getLogger("aibrain.integrations.recovery")


class IntegrationDispatchRecoveryWorker:
    def __init__(
        self,
        orchestrator,
        *,
        interval_seconds: int = 60,
        stale_after_seconds: int = 300,
    ) -> None:
        if interval_seconds <= 0 or stale_after_seconds <= 0:
            raise ValueError("Integration dispatch recovery intervals must be positive")
        self.orchestrator = orchestrator
        self.interval_seconds = interval_seconds
        self.stale_after_seconds = stale_after_seconds
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def run_once(self) -> int:
        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(seconds=self.stale_after_seconds)
        ).isoformat()
        return await asyncio.to_thread(
            self.orchestrator.recover_stale_dispatches,
            stale_before=cutoff,
        )

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._run(),
            name="integration-dispatch-recovery",
        )

    async def stop(self) -> None:
        task = self._task
        if task is None:
            return
        self._stop_event.set()
        await task
        self._task = None

    async def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                recovered = await self.run_once()
                if recovered:
                    logger.warning(
                        "Classified %s abandoned integration dispatch(es) as outcome-unknown",
                        recovered,
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Integration dispatch recovery cycle failed")

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.interval_seconds,
                )
            except asyncio.TimeoutError:
                continue
