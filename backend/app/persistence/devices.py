"""Owner-scoped device enrollment and revocation persistence."""
import json
import uuid
from datetime import datetime, timezone

from backend.app.devices.contracts import (
    DeviceCapabilityReport,
    DeviceRecord,
    DeviceRegistrationRequest,
)
from backend.app.persistence.contracts import DatabaseProtocol


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceRepository:
    def __init__(self, database: DatabaseProtocol) -> None:
        self.database = database

    def _transaction(self):
        """Preserve SQLite writer serialization and use PostgreSQL row locks."""
        dialect = getattr(self.database, "dialect", None)
        if dialect not in {"sqlite", "postgresql"}:
            raise RuntimeError("Unsupported database dialect for device repository")
        return self.database.transaction(immediate=(dialect == "sqlite"))

    def _lock_owner(self, connection, owner_id: str) -> None:
        if getattr(self.database, "dialect", None) != "postgresql":
            return
        row = connection.execute(
            "SELECT id FROM users WHERE id=? AND deleted_at IS NULL FOR UPDATE",
            (owner_id,),
        ).fetchone()
        if row is None:
            raise LookupError("Device owner not found")

    def _lock_owned_device(self, connection, owner_id: str, device_id: str) -> None:
        if getattr(self.database, "dialect", None) != "postgresql":
            return
        self._lock_owner(connection, owner_id)
        row = connection.execute(
            "SELECT id FROM devices WHERE id=? AND user_id=? FOR UPDATE",
            (device_id, owner_id),
        ).fetchone()
        if row is None:
            raise LookupError("Device not found")

    @staticmethod
    def _record(row) -> DeviceRecord:
        return DeviceRecord(
            device_id=row["id"],
            owner_id=row["user_id"],
            platform=row["platform"],
            app_version=row["app_version"],
            display_name=row["display_name"],
            public_key_fingerprint=row["public_key_fingerprint"],
            status=row["status"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            last_seen_at=(
                datetime.fromisoformat(row["last_seen_at"])
                if row["last_seen_at"] else None
            ),
            revoked_at=(
                datetime.fromisoformat(row["revoked_at"])
                if row["revoked_at"] else None
            ),
        )

    def enroll(
        self,
        owner_id: str,
        request: DeviceRegistrationRequest,
    ) -> DeviceRecord:
        device_id = str(uuid.uuid4())
        now = _now()
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner(connection, owner_id)
            connection.execute(
                """
                INSERT INTO devices (
                    id, user_id, platform, app_version, display_name,
                    public_key_fingerprint, status, enrolled_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (
                    device_id,
                    owner_id,
                    request.platform.value,
                    request.app_version,
                    request.display_name,
                    request.public_key_fingerprint.lower(),
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM devices WHERE id = ? AND user_id = ?",
                (device_id, owner_id),
            ).fetchone()
        return self._record(row)

    def list_owned(self, owner_id: str) -> tuple[DeviceRecord, ...]:
        rows = self.database.connect().execute(
            """
            SELECT * FROM devices
            WHERE user_id = ?
            ORDER BY enrolled_at DESC, id
            """,
            (owner_id,),
        ).fetchall()
        return tuple(self._record(row) for row in rows)

    def get_owned(self, owner_id: str, device_id: str) -> DeviceRecord:
        row = self.database.connect().execute(
            "SELECT * FROM devices WHERE id = ? AND user_id = ?",
            (device_id, owner_id),
        ).fetchone()
        if row is None:
            raise LookupError("Device not found")
        return self._record(row)

    def confirm(self, owner_id: str, device_id: str) -> DeviceRecord:
        """Legacy confirmation is disabled; activation requires key proof."""
        row = self.database.connect().execute(
            "SELECT id FROM devices WHERE id = ? AND user_id = ?",
            (device_id, owner_id),
        ).fetchone()
        if row is None:
            raise LookupError("Device not found")
        raise PermissionError("Device activation requires cryptographic proof")

    def revoke(self, owner_id: str, device_id: str) -> DeviceRecord:
        now = _now()
        dialect = getattr(self.database, "dialect", None)
        if dialect not in {"sqlite", "postgresql"}:
            raise RuntimeError("Unsupported database dialect for device revocation")
        with self._transaction():
            connection = self.database.connect()
            if dialect == "postgresql":
                self._lock_owned_device(connection, owner_id, device_id)
            cursor = connection.execute(
                """
                UPDATE devices
                SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?)
                WHERE id = ? AND user_id = ? AND status <> 'revoked'
                """,
                (now, device_id, owner_id),
            )
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT status FROM devices WHERE id = ? AND user_id = ?",
                    (device_id, owner_id),
                ).fetchone()
                if row is None:
                    raise LookupError("Device not found")
            # Device revocation and session invalidation share one write
            # transaction, so no new request can observe a revoked device
            # with still-valid device-bound sessions.
            connection.execute(
                """
                UPDATE sessions
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE device_id = ? AND user_id = ? AND revoked_at IS NULL
                """,
                (now, device_id, owner_id),
            )
        return self.get_owned(owner_id, device_id)

    def record_capabilities(
        self,
        owner_id: str,
        device_id: str,
        report: DeviceCapabilityReport,
    ) -> DeviceRecord:
        capabilities = sorted({item.value for item in report.capabilities})
        with self._transaction():
            connection = self.database.connect()
            self._lock_owned_device(connection, owner_id, device_id)
            cursor = connection.execute(
                """
                UPDATE devices
                SET capability_report_json = ?,
                    capability_reported_at = ?,
                    last_seen_at = ?
                WHERE id = ? AND user_id = ? AND status = 'active'
                """,
                (
                    json.dumps(capabilities, separators=(",", ":")),
                    report.reported_at.isoformat(),
                    _now(),
                    device_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT status FROM devices WHERE id = ? AND user_id = ?",
                    (device_id, owner_id),
                ).fetchone()
                if row is None:
                    raise LookupError("Device not found")
                raise PermissionError("Only active devices may report capabilities")
        return self.get_owned(owner_id, device_id)
