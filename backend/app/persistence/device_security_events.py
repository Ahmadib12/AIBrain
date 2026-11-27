"""Owner-scoped, append-only device security event history."""
import json
import uuid
from datetime import datetime, timezone

from backend.app.persistence.contracts import DatabaseProtocol


_ALLOWED_EVENTS = frozenset({
    "device.enrolled",
    "device.key_registered",
    "device.activated",
    "device.revoked",
    "device.session_authenticated",
    "device.login_authenticated",
    "device.key_rotated",
})


class DeviceSecurityEventRepository:
    """Persists minimal security events; never stores credentials or proofs."""

    def __init__(self, database: DatabaseProtocol) -> None:
        self.database = database

    def _transaction(self):
        dialect = getattr(self.database, "dialect", None)
        if dialect not in {"sqlite", "postgresql"}:
            raise RuntimeError("Unsupported database dialect for device security events")
        return self.database.transaction(immediate=(dialect == "sqlite"))

    def _lock_owner_device(self, connection, owner_id: str, device_id: str) -> None:
        if getattr(self.database, "dialect", None) != "postgresql":
            return
        owner = connection.execute(
            "SELECT id FROM users WHERE id=? AND deleted_at IS NULL FOR UPDATE",
            (owner_id,),
        ).fetchone()
        if owner is None:
            raise LookupError("Device event owner not found")
        device = connection.execute(
            "SELECT id FROM devices WHERE id=? AND user_id=? FOR UPDATE",
            (device_id, owner_id),
        ).fetchone()
        if device is None:
            raise LookupError("Device not found")

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
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            connection.execute(
                """
                INSERT INTO device_security_events
                    (id, user_id, device_id, event_type, occurred_at, details_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), owner_id, device_id, event_type,
                    datetime.now(timezone.utc).isoformat(), encoded,
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
