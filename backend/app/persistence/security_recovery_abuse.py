"""Shared recovery-abuse counters for SQLite and distributed Redis deployments."""
from __future__ import annotations

import hmac
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from backend.app.persistence.contracts import DatabaseProtocol


class RecoveryAbuseUnavailable(RuntimeError):
    """The configured shared abuse-control service could not be reached."""


class SecurityRecoveryAbuseMonitor:
    """SQLite fixed-window monitor for local development and single-host use."""

    def __init__(self, database: DatabaseProtocol) -> None:
        self.database = database

    def check_and_record(
        self,
        email: str,
        *,
        source_ip: str | None = None,
        limit: int = 5,
        ip_limit: int = 30,
        window_seconds: int = 300,
    ) -> bool:
        if not 1 <= limit <= 100 or not 1 <= ip_limit <= 1_000 or not 1 <= window_seconds <= 86_400:
            raise ValueError("Recovery abuse monitor bounds are invalid")
        now = int(datetime.now(timezone.utc).timestamp())
        window_start = now - (now % window_seconds)
        account_scope = sha256(("account:" + email.strip().lower()).encode("utf-8")).hexdigest()
        scopes = [(account_scope, limit)]
        if source_ip:
            ip_scope = sha256(("source-ip:" + source_ip).encode("utf-8")).hexdigest()
            scopes.append((ip_scope, ip_limit))
        now_text = datetime.now(timezone.utc).isoformat()
        allowed = True
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            for scope, scope_limit in scopes:
                connection.execute(
                    """
                    INSERT INTO security_recovery_abuse_windows
                        (scope_hash, window_start, attempts, blocked_attempts, updated_at)
                    VALUES (?, ?, 1, 0, ?)
                    ON CONFLICT(scope_hash, window_start) DO UPDATE SET
                        attempts=attempts+1, updated_at=excluded.updated_at
                    """,
                    (scope, window_start, now_text),
                )
                row = connection.execute(
                    """
                    SELECT attempts FROM security_recovery_abuse_windows
                    WHERE scope_hash=? AND window_start=?
                    """,
                    (scope, window_start),
                ).fetchone()
                if int(row["attempts"]) > scope_limit:
                    allowed = False
                    connection.execute(
                        """
                        UPDATE security_recovery_abuse_windows
                        SET blocked_attempts=blocked_attempts+1
                        WHERE scope_hash=? AND window_start=?
                        """,
                        (scope, window_start),
                    )
            connection.execute(
                "DELETE FROM security_recovery_abuse_windows WHERE window_start < ?",
                (window_start - 2 * window_seconds,),
            )
        return allowed

    def metrics(self) -> dict[str, int]:
        row = self.database.connect().execute(
            """
            SELECT COALESCE(SUM(attempts),0) AS attempts,
                   COALESCE(SUM(blocked_attempts),0) AS blocked_attempts,
                   COUNT(*) AS active_scopes
            FROM security_recovery_abuse_windows
            """
        ).fetchone()
        return {key: int(row[key]) for key in ("attempts", "blocked_attempts", "active_scopes")}


_REDIS_CHECK_SCRIPT = """
local ttl = tonumber(ARGV[1])
local window_seconds = tonumber(ARGV[2])
local expected_window_start = tonumber(ARGV[3])
local now = tonumber(redis.call('TIME')[1])
local actual_window_start = now - (now % window_seconds)
if actual_window_start ~= expected_window_start then
    return {-1, 0}
end
local scope_count = tonumber(ARGV[4])
local blocked = 0
local blocked_scopes = 0
local active_scopes = 0
for i = 1, scope_count do
    local scope_key = KEYS[i + 1]
    local scope_limit = tonumber(ARGV[i + 4])
    local count = redis.call('INCR', scope_key)
    if count == 1 then
        redis.call('EXPIRE', scope_key, ttl)
        active_scopes = active_scopes + 1
    end
    if count > scope_limit then
        blocked = 1
        blocked_scopes = blocked_scopes + 1
    end
end
redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if active_scopes > 0 then
    redis.call('HINCRBY', KEYS[1], 'active_scopes', active_scopes)
end
if blocked_scopes > 0 then
    redis.call('HINCRBY', KEYS[1], 'blocked_attempts', blocked_scopes)
end
redis.call('EXPIRE', KEYS[1], ttl)
return {1 - blocked, blocked}
"""


class RedisSecurityRecoveryAbuseMonitor:
    """Atomic cross-process/cross-host fixed-window monitor backed by shared Redis."""

    def __init__(
        self,
        redis_client: Any,
        *,
        hmac_key: str,
        key_prefix: str = "aibrain:recovery-abuse:v1",
        metrics_window_seconds: int = 300,
    ) -> None:
        if len(hmac_key.encode("utf-8")) < 32:
            raise ValueError("Recovery abuse HMAC key must contain at least 32 bytes")
        if not key_prefix or len(key_prefix) > 128 or any(ch.isspace() for ch in key_prefix) or "{" in key_prefix or "}" in key_prefix:
            raise ValueError("Recovery abuse Redis key prefix is invalid")
        if not 1 <= metrics_window_seconds <= 86_400:
            raise ValueError("Recovery abuse metrics window is invalid")
        self.redis = redis_client
        self.hmac_key = hmac_key.encode("utf-8")
        self.key_prefix = key_prefix
        self.metrics_window_seconds = metrics_window_seconds

    def _digest(self, scope: str) -> str:
        return hmac.new(self.hmac_key, scope.encode("utf-8"), sha256).hexdigest()

    def check_and_record(
        self,
        email: str,
        *,
        source_ip: str | None = None,
        limit: int = 5,
        ip_limit: int = 30,
        window_seconds: int = 300,
    ) -> bool:
        if not 1 <= limit <= 100 or not 1 <= ip_limit <= 1_000 or not 1 <= window_seconds <= 86_400:
            raise ValueError("Recovery abuse monitor bounds are invalid")
        ttl = window_seconds * 3
        scopes = [
            (self._digest("account:" + email.strip().lower()), limit),
        ]
        if source_ip:
            scopes.append((self._digest("source-ip:" + source_ip), ip_limit))
        try:
            # Redis TIME provides one authoritative window clock for every
            # application host. The script checks the window again atomically.
            for _attempt in range(2):
                redis_seconds, _microseconds = self.redis.time()
                now = int(redis_seconds)
                window_start = now - (now % window_seconds)
                # A shared hash tag keeps every key in one Redis Cluster slot.
                base = f"{self.key_prefix}:{{recovery-abuse}}:{window_seconds}:{window_start}"
                metric_key = f"{base}:metrics"
                keys = [metric_key]
                args: list[Any] = [ttl, window_seconds, window_start, len(scopes)]
                for digest, scope_limit in scopes:
                    keys.append(f"{base}:scope:{digest}")
                    args.append(scope_limit)
                result = self.redis.eval(
                    _REDIS_CHECK_SCRIPT, len(keys), *keys, *args
                )
                if int(result[0]) >= 0:
                    return bool(int(result[0]))
            raise RecoveryAbuseUnavailable(
                "Shared recovery abuse window changed during request"
            )
        except RecoveryAbuseUnavailable:
            raise
        except Exception as exc:
            raise RecoveryAbuseUnavailable(
                "Shared recovery abuse protection is unavailable"
            ) from exc

    def metrics(self) -> dict[str, int]:
        window = self.metrics_window_seconds
        totals = {"attempts": 0, "blocked_attempts": 0, "active_scopes": 0}
        try:
            redis_seconds, _microseconds = self.redis.time()
            now = int(redis_seconds)
            current_start = now - (now % window)
            for offset in range(3):
                key = f"{self.key_prefix}:{{recovery-abuse}}:{window}:{current_start - (offset * window)}:metrics"
                values = self.redis.hgetall(key)
                for field in totals:
                    totals[field] += int(values.get(field, 0))
        except Exception as exc:
            raise RecoveryAbuseUnavailable(
                "Shared recovery abuse metrics are unavailable"
            ) from exc
        return totals

    def close(self) -> None:
        close = getattr(self.redis, "close", None)
        if close is not None:
            close()
