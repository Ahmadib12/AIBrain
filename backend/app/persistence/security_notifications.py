"""Durable outbox for security notifications.

The outbox stores only the destination and a minimal event payload. Delivery is
performed by a separate worker/adapter; database transactions never send email.
"""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

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
                SET status='pending', claimed_at=NULL, claim_token=NULL
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
                claim_token = str(uuid4())
                cursor = connection.execute(
                    """
                    UPDATE security_notification_outbox
                    SET status='processing', claimed_at=?, attempts=attempts+1,
                        claim_token=?
                    WHERE id=? AND status='pending'
                    """,
                    (now_text, claim_token, row["id"]),
                )
                if cursor.rowcount != 1:
                    continue
                item = connection.execute(
                    """
                    SELECT id, event_id, user_id, recipient_email,
                           notification_type, payload_json, attempts, created_at, claim_token
                    FROM security_notification_outbox WHERE id=?
                    """,
                    (row["id"],),
                ).fetchone()
                claimed.append(dict(item))
        return tuple(claimed)

    def renew_claim(self, notification_id: str, *, lease_seconds: int = 600, claim_token: str | None = None) -> bool:
        if not 1 <= lease_seconds <= 3_600:
            raise ValueError("Notification lease bounds are invalid")
        now = _now().isoformat()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """
                UPDATE security_notification_outbox
                SET claimed_at=?
                WHERE id=? AND status='processing'
                  AND (? IS NULL OR claim_token=?)
                """,
                (now, notification_id, claim_token, claim_token),
            )
            return cursor.rowcount == 1

    def mark_delivered(self, notification_id: str, *, claim_token: str | None = None) -> bool:
        now = _now().isoformat()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """
                UPDATE security_notification_outbox
                SET status='delivered', delivered_at=?, claimed_at=NULL, claim_token=NULL
                WHERE id=? AND status='processing'
                  AND (? IS NULL OR claim_token=?)
                """,
                (now, notification_id, claim_token, claim_token),
            )
            return cursor.rowcount == 1

    def release_for_retry(
        self,
        notification_id: str,
        *,
        delay_seconds: int,
        max_attempts: int = 8,
        claim_token: str | None = None,
    ) -> bool:
        if not 1 <= delay_seconds <= 86_400 or not 1 <= max_attempts <= 100:
            raise ValueError("Notification retry bounds are invalid")
        now = _now()
        available = (now + timedelta(seconds=delay_seconds)).isoformat()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                "SELECT attempts FROM security_notification_outbox "
                "WHERE id=? AND status='processing' AND (? IS NULL OR claim_token=?)",
                (notification_id, claim_token, claim_token),
            ).fetchone()
            if row is None:
                return False
            if int(row["attempts"]) >= max_attempts:
                cursor = connection.execute(
                    """
                    UPDATE security_notification_outbox
                    SET status='failed', failed_at=?, failure_code=?, claimed_at=NULL, claim_token=NULL
                    WHERE id=? AND status='processing' AND (? IS NULL OR claim_token=?)
                    """,
                    (now.isoformat(), "delivery_attempts_exhausted", notification_id, claim_token, claim_token),
                )
            else:
                cursor = connection.execute(
                    """
                    UPDATE security_notification_outbox
                    SET status='pending', available_at=?, claimed_at=NULL, claim_token=NULL
                    WHERE id=? AND status='processing' AND (? IS NULL OR claim_token=?)
                    """,
                    (available, notification_id, claim_token, claim_token),
                )
            return cursor.rowcount == 1

    def delivery_counts(self) -> dict[str, int]:
        rows = self.database.connect().execute(
            "SELECT status, COUNT(*) AS total FROM security_notification_outbox GROUP BY status"
        ).fetchall()
        counts = {"pending": 0, "processing": 0, "delivered": 0, "failed": 0}
        counts.update({row["status"]: int(row["total"]) for row in rows})
        return counts

    def pending_count(self) -> int:
        row = self.database.connect().execute(
            "SELECT COUNT(*) AS total FROM security_notification_outbox "
            "WHERE status IN ('pending','processing')"
        ).fetchone()
        return int(row["total"])
