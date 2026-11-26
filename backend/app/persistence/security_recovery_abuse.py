"""Shared-database fixed-window abuse counters for lost-device recovery."""
from datetime import datetime, timezone
from hashlib import sha256


class SecurityRecoveryAbuseMonitor:
    """Coordinates account-scoped rate limits across processes sharing a database.

    Only one-way digests of the normalized account email and direct peer IP
    are persisted. A shared database is required for cross-host coordination.
    """

    def __init__(self, database) -> None:
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
            # Retain only recent aggregate windows; raw account/IP identifiers
            # are never stored in this table.
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
