"""Shared-database fixed-window abuse counters for lost-device recovery."""
from datetime import datetime, timezone
from hashlib import sha256


class SecurityRecoveryAbuseMonitor:
    """Coordinates account-scoped rate limits across processes sharing a database.

    Only a one-way digest of the normalized account email is persisted. A
    shared database is required for cross-host coordination.
    """

    def __init__(self, database) -> None:
        self.database = database

    def check_and_record(
        self, email: str, *, limit: int = 5, window_seconds: int = 300
    ) -> bool:
        if not 1 <= limit <= 100 or not 1 <= window_seconds <= 86_400:
            raise ValueError("Recovery abuse monitor bounds are invalid")
        now = int(datetime.now(timezone.utc).timestamp())
        window_start = now - (now % window_seconds)
        # Account-scoped throttling prevents bypass by rotating device IDs.
        scope = sha256(email.strip().lower().encode("utf-8")).hexdigest()
        now_text = datetime.now(timezone.utc).isoformat()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
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
            allowed = int(row["attempts"]) <= limit
            if not allowed:
                connection.execute(
                    """
                    UPDATE security_recovery_abuse_windows
                    SET blocked_attempts=blocked_attempts+1
                    WHERE scope_hash=? AND window_start=?
                    """,
                    (scope, window_start),
                )
            # Retain only recent aggregate windows; no raw account/device identifiers.
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
