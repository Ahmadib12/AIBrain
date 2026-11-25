"""Owner-scoped, append-only device security event history."""
import json
import uuid
from datetime import datetime, timezone

from backend.app.persistence.database import Database


_ALLOWED_EVENTS = frozenset({
    "device.enrolled",
    "device.key_registered",
    "device.activated",
    "device.revoked",
    "device.session_authenticated",
    "device.login_authenticated",
})


class DeviceSecurityEventRepository:
    """Persists minimal security events; never stores credentials or proofs."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def record(
        self,
        owner_id: str,
        device_id: str,
        event_type: str,
        *,
        details: dict | None = None,
    ) -> None:
        if event_type not in _ALLOWED_EVENTS:
            raise ValueError("Unsupported device security event")
        # Details are intentionally constrained to non-secret, bounded metadata.
        safe_details = details or {}
        if not isinstance(safe_details, dict) or len(safe_details) > 8:
            raise ValueError("Invalid event details")
        encoded = json.dumps(safe_details, separators=(",", ":"), sort_keys=True)
        if len(encoded) > 1024:
            raise ValueError("Event details are too large")
        with self.database.transaction(immediate=True):
            self.database.connect().execute(
                """
                INSERT INTO device_security_events
                    (id, user_id, device_id, event_type, occurred_at, details_json)
                SELECT ?, ?, ?, ?, ?, ?
                WHERE EXISTS (
                    SELECT 1 FROM devices
                    WHERE id=? AND user_id=?
                )
                """,
                (
                    str(uuid.uuid4()), owner_id, device_id, event_type,
                    datetime.now(timezone.utc).isoformat(), encoded,
                    device_id, owner_id,
                ),
            )

    def list_owned(
        self, owner_id: str, *, limit: int = 50,
        before_occurred_at: str | None = None, before_event_id: str | None = None,
    ) -> tuple[dict, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("Event page size must be between 1 and 100")
        if (before_occurred_at is None) != (before_event_id is None):
            raise ValueError("Both event cursor fields must be supplied together")
        if before_occurred_at is None:
            rows = self.database.connect().execute(
                """
                SELECT id, device_id, event_type, occurred_at, details_json
                FROM device_security_events
                WHERE user_id=?
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
                """,
                (owner_id, limit),
            ).fetchall()
        else:
            rows = self.database.connect().execute(
                """
                SELECT id, device_id, event_type, occurred_at, details_json
                FROM device_security_events
                WHERE user_id=?
                  AND (occurred_at < ? OR (occurred_at = ? AND id < ?))
                ORDER BY occurred_at DESC, id DESC
                LIMIT ?
                """,
                (owner_id, before_occurred_at, before_occurred_at, before_event_id, limit),
            ).fetchall()
        return tuple({
            "event_id": row["id"],
            "device_id": row["device_id"],
            "event_type": row["event_type"],
            "occurred_at": row["occurred_at"],
            "details": json.loads(row["details_json"]),
        } for row in rows)
