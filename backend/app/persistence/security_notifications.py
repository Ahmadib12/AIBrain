"""Durable outbox for security notifications.

The outbox stores only the destination and a minimal event payload. Delivery is
performed by a separate worker/adapter; database transactions never send email.
"""
import uuid
from datetime import datetime, timedelta, timezone

from backend.app.persistence.database import Database


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SecurityNotificationOutbox:
    def __init__(self, database: Database) -> None:
        self.database = database

    def claim_batch(
        self,
        *,
        limit: int = 20,
        lease_seconds: int = 300,
    ) -> tuple[dict, ...]:
        if not 1 <= limit <= 100 or lease_seconds < 1:
            raise ValueError("Notification claim bounds are invalid")
        now = _now()
        now_text = now.isoformat()
        stale_before = (now - timedelta(seconds=lease_seconds)).isoformat()
        claimed: list[dict] = []
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            # A process that died while sending cannot strand rows forever.
            connection.execute(
                """
                UPDATE security_notification_outbox
                SET status='pending', claimed_at=NULL
                WHERE status='processing' AND claimed_at <= ?
                """,
                (stale_before,),
            )
            rows = connection.execute(
                """
                SELECT id FROM security_notification_outbox
                WHERE status='pending' AND available_at <= ?
                ORDER BY available_at, created_at, id
                LIMIT ?
                """,
                (now_text, limit),
            ).fetchall()
            for row in rows:
                cursor = connection.execute(
                    """
                    UPDATE security_notification_outbox
                    SET status='processing', claimed_at=?, attempts=attempts+1
                    WHERE id=? AND status='pending'
                    """,
                    (now_text, row["id"]),
                )
                if cursor.rowcount != 1:
                    continue
                item = connection.execute(
                    """
                    SELECT id, event_id, user_id, recipient_email,
                           notification_type, payload_json, attempts, created_at
                    FROM security_notification_outbox WHERE id=?
                    """,
                    (row["id"],),
                ).fetchone()
                claimed.append(dict(item))
        return tuple(claimed)

    def mark_delivered(self, notification_id: str) -> bool:
        now = _now().isoformat()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """
                UPDATE security_notification_outbox
                SET status='delivered', delivered_at=?, claimed_at=NULL
                WHERE id=? AND status='processing'
                """,
                (now, notification_id),
            )
            return cursor.rowcount == 1

    def release_for_retry(
        self,
        notification_id: str,
        *,
        delay_seconds: int,
    ) -> bool:
        if not 1 <= delay_seconds <= 86_400:
            raise ValueError("Notification retry delay is invalid")
        available = (_now() + timedelta(seconds=delay_seconds)).isoformat()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """
                UPDATE security_notification_outbox
                SET status='pending', available_at=?, claimed_at=NULL
                WHERE id=? AND status='processing'
                """,
                (available, notification_id),
            )
            return cursor.rowcount == 1

    def pending_count(self) -> int:
        row = self.database.connect().execute(
            "SELECT COUNT(*) AS total FROM security_notification_outbox "
            "WHERE status IN ('pending','processing')"
        ).fetchone()
        return int(row["total"])
