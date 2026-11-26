"""Audited operator review and controlled redrive for dead-letter notifications."""
from datetime import datetime, timezone
from uuid import uuid4

from backend.app.persistence.database import Database


class SecurityNotificationOperations:
    def __init__(self, database: Database) -> None:
        self.database = database

    def list_dead_letters(self, *, limit: int = 50) -> tuple[dict, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("Dead-letter page size must be between 1 and 100")
        rows = self.database.connect().execute(
            """
            SELECT id, event_id, notification_type, status, attempts,
                   failed_at, failure_code, created_at, redrive_count
            FROM security_notification_outbox
            WHERE status='failed'
            ORDER BY failed_at DESC, id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def redrive(self, notification_id: str, *, operator_user_id: str, reason: str) -> bool:
        reason = reason.strip()
        if not 10 <= len(reason) <= 500:
            raise ValueError("Redrive reason must contain 10 to 500 characters")
        now = datetime.now(timezone.utc).isoformat()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                "SELECT id FROM security_notification_outbox WHERE id=? AND status='failed'",
                (notification_id,),
            ).fetchone()
            if row is None:
                return False
            changed = connection.execute(
                """
                UPDATE security_notification_outbox
                SET status='pending', attempts=0, available_at=?, claimed_at=NULL,
                    failed_at=NULL, failure_code=NULL,
                    redrive_count=redrive_count+1
                WHERE id=? AND status='failed'
                """,
                (now, notification_id),
            )
            if changed.rowcount != 1:
                return False
            connection.execute(
                """
                INSERT INTO security_notification_operator_events
                    (id, notification_id, operator_user_id, action, reason, created_at)
                VALUES (?, ?, ?, 'redrive', ?, ?)
                """,
                (str(uuid4()), notification_id, operator_user_id, reason, now),
            )
            return True

    def notification_events(self, notification_id: str, *, limit: int = 50) -> tuple[dict, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("Audit page size must be between 1 and 100")
        rows = self.database.connect().execute(
            """
            SELECT id, notification_id, operator_user_id, action, reason, created_at
            FROM security_notification_operator_events
            WHERE notification_id=?
            ORDER BY created_at DESC, id
            LIMIT ?
            """,
            (notification_id, limit),
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def metrics(self) -> dict:
        connection = self.database.connect()
        rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM security_notification_outbox GROUP BY status"
        ).fetchall()
        counts = {"pending": 0, "processing": 0, "delivered": 0, "failed": 0}
        counts.update({row["status"]: int(row["total"]) for row in rows})
        oldest = connection.execute(
            "SELECT MIN(created_at) AS oldest FROM security_notification_outbox "
            "WHERE status IN ('pending','processing')"
        ).fetchone()["oldest"]
        age = None
        if oldest:
            timestamp = datetime.fromisoformat(oldest)
            age = max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds()))
        return {
            "counts": counts,
            "active": counts["pending"] + counts["processing"],
            "oldest_active_age_seconds": age,
        }
