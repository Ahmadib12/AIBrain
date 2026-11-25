"""Owner-scoped, append-only session security history."""

from datetime import datetime
from uuid import UUID

from backend.app.persistence.database import Database


class SessionSecurityEventRepository:
    """Reads minimal session lifecycle events emitted by database triggers."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def list_owned(
        self,
        owner_id: str,
        *,
        limit: int = 50,
        before_occurred_at: str | None = None,
        before_event_id: str | None = None,
    ) -> tuple[dict, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("Event page size must be between 1 and 100")
        if (before_occurred_at is None) != (before_event_id is None):
            raise ValueError("Both event cursor fields must be supplied together")
        if before_occurred_at is not None:
            try:
                datetime.fromisoformat(before_occurred_at)
                UUID(before_event_id)
            except (TypeError, ValueError):
                raise ValueError("Invalid session event cursor") from None

        if before_occurred_at is None:
            rows = self.database.connect().execute(
                """
                SELECT id, device_id, auth_method, event_type, occurred_at
                FROM session_security_events
                WHERE user_id=?
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
                """,
                (owner_id, limit),
            ).fetchall()
        else:
            rows = self.database.connect().execute(
                """
                SELECT id, device_id, auth_method, event_type, occurred_at
                FROM session_security_events
                WHERE user_id=?
                  AND (occurred_at < ? OR (occurred_at = ? AND id < ?))
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
                """,
                (
                    owner_id,
                    before_occurred_at,
                    before_occurred_at,
                    before_event_id,
                    limit,
                ),
            ).fetchall()

        return tuple(
            {
                "event_id": row["id"],
                "device_id": row["device_id"],
                "auth_method": row["auth_method"],
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
            }
            for row in rows
        )
