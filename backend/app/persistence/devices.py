"""Owner-scoped device enrollment and revocation persistence."""
import json
import uuid
from datetime import datetime, timezone

from backend.app.devices.contracts import (
    DeviceCapabilityReport,
    DeviceLifecycleStatus,
    DeviceRecord,
    DeviceRegistrationRequest,
)
from backend.app.persistence.database import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

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
        with self.database.transaction(immediate=True):
            self.database.connect().execute(
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
            row = self.database.connect().execute(
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
        now = _now()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """
                UPDATE devices SET status = 'active', last_seen_at = ?
                WHERE id = ? AND user_id = ? AND status = 'pending'
                """,
                (now, device_id, owner_id),
            )
            if cursor.rowcount != 1:
                row = self.database.connect().execute(
                    "SELECT status FROM devices WHERE id = ? AND user_id = ?",
                    (device_id, owner_id),
                ).fetchone()
                if row is None:
                    raise LookupError("Device not found")
                raise ValueError("Only a pending device can be confirmed")
        return self.get_owned(owner_id, device_id)

    def revoke(self, owner_id: str, device_id: str) -> DeviceRecord:
        now = _now()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """
                UPDATE devices
                SET status = 'revoked', revoked_at = COALESCE(revoked_at, ?)
                WHERE id = ? AND user_id = ? AND status <> 'revoked'
                """,
                (now, device_id, owner_id),
            )
            if cursor.rowcount != 1:
                row = self.database.connect().execute(
                    "SELECT status FROM devices WHERE id = ? AND user_id = ?",
                    (device_id, owner_id),
                ).fetchone()
                if row is None:
                    raise LookupError("Device not found")
        return self.get_owned(owner_id, device_id)

    def record_capabilities(
        self,
        owner_id: str,
        device_id: str,
        report: DeviceCapabilityReport,
    ) -> DeviceRecord:
        capabilities = sorted({item.value for item in report.capabilities})
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
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
                row = self.database.connect().execute(
                    "SELECT status FROM devices WHERE id = ? AND user_id = ?",
                    (device_id, owner_id),
                ).fetchone()
                if row is None:
                    raise LookupError("Device not found")
                raise PermissionError("Only active devices may report capabilities")
        return self.get_owned(owner_id, device_id)
