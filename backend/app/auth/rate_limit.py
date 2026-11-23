from collections import OrderedDict
import threading
import time


class LoginRateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: int,
        max_entries: int = 10_000,
    ) -> None:
        if limit < 1 or window_seconds < 1 or max_entries < 1:
            raise ValueError("Login rate-limit configuration is invalid")

        self.limit = limit
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._attempts: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()
        self._cleanup_interval_seconds = 60

    def _cleanup_expired(self, now: float) -> None:
        if now - self._last_cleanup < self._cleanup_interval_seconds:
            return

        expired = [
            key
            for key, timestamps in self._attempts.items()
            if not any(
                now - timestamp < self.window_seconds
                for timestamp in timestamps
            )
        ]
        for key in expired:
            self._attempts.pop(key, None)

        self._last_cleanup = now

    def _active_timestamps(self, key: str, now: float) -> list[float]:
        return [
            timestamp
            for timestamp in self._attempts.get(key, [])
            if now - timestamp < self.window_seconds
        ]

    def is_limited(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._cleanup_expired(now)
            timestamps = self._active_timestamps(key, now)

            if timestamps:
                self._attempts[key] = timestamps
                self._attempts.move_to_end(key)
            else:
                self._attempts.pop(key, None)

            return len(timestamps) >= self.limit

    def check_and_record(self, key: str) -> bool:
        """Atomically allow and record an attempt below the configured limit."""
        now = time.monotonic()
        with self._lock:
            self._cleanup_expired(now)
            timestamps = self._active_timestamps(key, now)

            if len(timestamps) >= self.limit:
                self._attempts[key] = timestamps
                self._attempts.move_to_end(key)
                return False

            timestamps.append(now)

            if key not in self._attempts:
                while len(self._attempts) >= self.max_entries:
                    self._attempts.popitem(last=False)

            self._attempts[key] = timestamps
            self._attempts.move_to_end(key)
            return True

    def record_attempt(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._cleanup_expired(now)
            timestamps = self._active_timestamps(key, now)
            timestamps.append(now)

            if key not in self._attempts:
                while len(self._attempts) >= self.max_entries:
                    self._attempts.popitem(last=False)

            self._attempts[key] = timestamps
            self._attempts.move_to_end(key)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
