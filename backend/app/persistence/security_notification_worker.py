"""Supervised asynchronous delivery worker for the security notification outbox."""
import asyncio
import logging

logger = logging.getLogger("aibrain.security_notifications")


class SecurityNotificationDeliveryWorker:
    def __init__(self, repository, transport, *, interval_seconds: int = 30, batch_size: int = 10) -> None:
        if interval_seconds < 1 or not 1 <= batch_size <= 100:
            raise ValueError("Security notification worker bounds are invalid")
        self.repository = repository
        self.transport = transport
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None

    async def run_once(self) -> int:
        batch = await asyncio.to_thread(self.repository.claim_batch, limit=self.batch_size)
        delivered = 0
        for notification in batch:
            notification_id = notification["id"]
            try:
                await asyncio.to_thread(self.transport.send, notification)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Exponential backoff is capped at one hour; never log message or recipient data.
                exponent = min(max(int(notification["attempts"]) - 1, 0), 7)
                delay = min(3_600, 30 * (2 ** exponent))
                try:
                    await asyncio.to_thread(
                        self.repository.release_for_retry,
                        notification_id,
                        delay_seconds=delay,
                    )
                except Exception:
                    logger.error("Security notification retry scheduling failed")
                else:
                    logger.warning("Security notification delivery failed; retry scheduled")
                continue
            marked = await asyncio.to_thread(self.repository.mark_delivered, notification_id)
            if marked:
                delivered += 1
            else:
                logger.warning("Security notification was sent but delivery state could not be finalized")
        return delivered

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        stop_event = asyncio.Event()
        self._stop_event = stop_event
        self._task = asyncio.create_task(self._run(stop_event), name="security-notification-delivery")

    async def _run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.error("Security notification delivery cycle failed")
            if stop_event.is_set():
                break
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.interval_seconds)
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
        # Do not cancel an in-flight SMTP/SQLite thread during shutdown.
        await task
