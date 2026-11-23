import json
import uuid
from datetime import datetime, timezone

from backend.app.persistence.database import Database
from backend.app.persistence.validation import validate_personal_payload


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MemoryRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(
        self,
        user_id: str,
        *,
        memory_type: str,
        key: str,
        value: object,
        source: str,
        confidence: float,
        expires_at: str | None = None,
    ) -> dict:
        if memory_type not in {"preference", "goal", "context", "project"}:
            raise ValueError("Unknown memory type")
        if not key.strip() or len(key) > 200:
            raise ValueError("Invalid memory key")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between zero and one")
        validate_personal_payload(value)
        if expires_at is not None:
            self._parse_expiration(expires_at)

        memory_id = str(uuid.uuid4())
        now = _utc_now()
        with self.database.transaction():
            self.database.connect().execute(
                "INSERT INTO memory_items "
                "(id, user_id, memory_type, key, value_json, source, "
                "confidence, status, expires_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                (
                    memory_id,
                    user_id,
                    memory_type,
                    key.strip(),
                    json.dumps(value, ensure_ascii=False),
                    source,
                    confidence,
                    expires_at,
                    now,
                    now,
                ),
            )
        row = self.database.connect().execute(
            "SELECT * FROM memory_items "
            "WHERE id = ? AND user_id = ?",
            (memory_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Memory not found")
        return self._to_dict(row)

    def get(self, user_id: str, memory_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM memory_items "
            "WHERE id = ? AND user_id = ?",
            (memory_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Memory not found")
        result = self._to_dict(row)
        if self._is_expired(result["expires_at"]):
            return self._expired_not_found()
        return result

    def list(self, user_id: str) -> tuple[dict, ...]:
        rows = self.database.connect().execute(
            "SELECT * FROM memory_items "
            "WHERE user_id = ? AND status = 'active' "
            "ORDER BY updated_at DESC",
            (user_id,),
        ).fetchall()
        active = []
        for row in rows:
            result = self._to_dict(row)
            if not self._is_expired(result["expires_at"]):
                active.append(result)
        return tuple(active)

    def update(
        self,
        user_id: str,
        memory_id: str,
        *,
        value: object,
        confidence: float,
    ) -> dict:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between zero and one")
        validate_personal_payload(value)
        now = _utc_now()
        with self.database.transaction():
            existing = self.database.connect().execute(
                "SELECT expires_at FROM memory_items "
                "WHERE id = ? AND user_id = ?",
                (memory_id, user_id),
            ).fetchone()
            if existing is None:
                raise LookupError("Memory not found")
            if self._is_expired(existing["expires_at"]):
                raise LookupError("Memory not found")
            cursor = self.database.connect().execute(
                "UPDATE memory_items "
                "SET value_json = ?, confidence = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ?",
                (
                    json.dumps(value, ensure_ascii=False),
                    confidence,
                    now,
                    memory_id,
                    user_id,
                ),
            )
            if cursor.rowcount != 1:
                raise LookupError("Memory not found")
        return self.get(user_id, memory_id)

    def delete(self, user_id: str, memory_id: str) -> bool:
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "DELETE FROM memory_items WHERE id = ? AND user_id = ?",
                (memory_id, user_id),
            )
        return cursor.rowcount == 1

    def delete_all(self, user_id: str) -> int:
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "DELETE FROM memory_items WHERE user_id = ?",
                (user_id,),
            )
        return cursor.rowcount

    def export(self, user_id: str) -> dict:
        return {
            "schema_version": 1,
            "user_id": user_id,
            "exported_at": _utc_now(),
            "memories": list(self.list(user_id)),
        }

    @staticmethod
    def _parse_expiration(expires_at: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(expires_at)
        except ValueError as error:
            raise ValueError("Invalid expiration timestamp") from error
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    @classmethod
    def _is_expired(cls, expires_at: str | None) -> bool:
        if expires_at is None:
            return False
        try:
            parsed = cls._parse_expiration(expires_at)
        except ValueError:
            return True
        return parsed <= datetime.now(timezone.utc)

    @staticmethod
    def _expired_not_found() -> dict:
        raise LookupError("Memory not found")

    @staticmethod
    def _to_dict(row) -> dict:
        return {
            "id": row["id"],
            "memory_type": row["memory_type"],
            "key": row["key"],
            "value": json.loads(row["value_json"]),
            "source": row["source"],
            "confidence": row["confidence"],
            "status": row["status"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
