import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.app.persistence.database import Database
from backend.app.persistence.validation import validate_personal_payload


_TOKEN_PATTERN = re.compile(r"[\\w-]{2,}", re.UNICODE)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime | None = None) -> str:
    return (value or _utc_now()).isoformat()


class MemoryRepository:
    """Owner-scoped memory storage gated by an explicit, revocable consent."""

    POLICY_VERSION = 1
    DEFAULT_RETENTION_DAYS = 365
    MAX_RETENTION_DAYS = 3650

    def __init__(self, database: Database) -> None:
        self.database = database

    def consent_status(self, user_id: str) -> dict[str, Any]:
        row = self.database.connect().execute(
            """
            SELECT id, purpose, policy_version, retention_days,
                   granted_at, revoked_at
            FROM memory_consents
            WHERE user_id = ? AND purpose = 'personal_memory'
            ORDER BY granted_at DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        if row is None:
            return {
                "status": "not_granted",
                "enabled": False,
                "policy_version": self.POLICY_VERSION,
                "retention_days": self.DEFAULT_RETENTION_DAYS,
                "granted_at": None,
                "revoked_at": None,
            }
        enabled = row["revoked_at"] is None
        return {
            "status": "active" if enabled else "revoked",
            "enabled": enabled,
            "policy_version": row["policy_version"],
            "retention_days": row["retention_days"],
            "granted_at": row["granted_at"],
            "revoked_at": row["revoked_at"],
        }

    def grant_consent(
        self,
        user_id: str,
        *,
        retention_days: int | None = DEFAULT_RETENTION_DAYS,
    ) -> dict[str, Any]:
        self._validate_retention_days(retention_days)
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            active_user = connection.execute(
                "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
            if active_user is None:
                raise sqlite3.IntegrityError("user account is not active")
            existing = connection.execute(
                """
                SELECT id FROM memory_consents
                WHERE user_id = ? AND purpose = 'personal_memory'
                  AND revoked_at IS NULL
                """,
                (user_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO memory_consents (
                        id, user_id, purpose, policy_version,
                        retention_days, granted_at, revoked_at
                    )
                    VALUES (?, ?, 'personal_memory', ?, ?, ?, NULL)
                    """,
                    (
                        str(uuid.uuid4()),
                        user_id,
                        self.POLICY_VERSION,
                        retention_days,
                        _utc_text(),
                    ),
                )
        return self.consent_status(user_id)

    def revoke_consent(
        self,
        user_id: str,
        *,
        purge_existing: bool = False,
    ) -> dict[str, Any]:
        deleted_count = 0
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            consent = connection.execute(
                """
                SELECT id FROM memory_consents
                WHERE user_id = ? AND purpose = 'personal_memory'
                  AND revoked_at IS NULL
                """,
                (user_id,),
            ).fetchone()
            if consent is not None:
                connection.execute(
                    "UPDATE memory_consents SET revoked_at = ? WHERE id = ?",
                    (_utc_text(), consent["id"]),
                )
                if purge_existing:
                    cursor = connection.execute(
                        "DELETE FROM memory_items "
                        "WHERE user_id = ? AND consent_id = ?",
                        (user_id, consent["id"]),
                    )
                    deleted_count = cursor.rowcount
        return {
            **self.consent_status(user_id),
            "revoked": consent is not None,
            "deleted_memories": deleted_count,
        }

    def set_retention_policy(
        self,
        user_id: str,
        *,
        retention_days: int | None,
    ) -> dict[str, Any]:
        self._validate_retention_days(retention_days)
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            consent = connection.execute(
                """
                SELECT id FROM memory_consents
                WHERE user_id = ? AND purpose = 'personal_memory'
                  AND revoked_at IS NULL
                """,
                (user_id,),
            ).fetchone()
            if consent is None:
                raise PermissionError("Active memory consent is required")
            connection.execute(
                "UPDATE memory_consents SET retention_days = ? WHERE id = ?",
                (retention_days, consent["id"]),
            )
            if retention_days is not None:
                rows = connection.execute(
                    """
                    SELECT id, created_at, expires_at FROM memory_items
                    WHERE user_id = ? AND consent_id = ?
                    """,
                    (user_id, consent["id"]),
                ).fetchall()
                for row in rows:
                    try:
                        created = self._parse_timestamp(row["created_at"])
                    except ValueError:
                        continue
                    policy_expiry = created + timedelta(days=retention_days)
                    current_expiry = row["expires_at"]
                    if current_expiry is not None:
                        try:
                            if self._parse_timestamp(current_expiry) <= policy_expiry:
                                continue
                        except ValueError:
                            pass
                    connection.execute(
                        "UPDATE memory_items SET expires_at = ? "
                        "WHERE id = ? AND user_id = ?",
                        (_utc_text(policy_expiry), row["id"], user_id),
                    )
        return self.consent_status(user_id)

    @classmethod
    def _validate_retention_days(cls, value: int | None) -> None:
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= cls.MAX_RETENTION_DAYS
        ):
            raise ValueError("Retention must be between 1 and 3650 days or null")

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError) as error:
            raise ValueError("Invalid timestamp") from error
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _is_expired(cls, expires_at: str | None) -> bool:
        if expires_at is None:
            return False
        try:
            return cls._parse_timestamp(expires_at) <= _utc_now()
        except ValueError:
            return True

    def _active_consent(self, user_id: str):
        connection = self.database.connect()
        user = connection.execute(
            "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL",
            (user_id,),
        ).fetchone()
        if user is None:
            # Preserve the database-level deleted-account boundary for callers
            # that raced with account deletion.
            raise sqlite3.IntegrityError("user account is not active")
        return connection.execute(
            """
            SELECT id, retention_days FROM memory_consents
            WHERE user_id = ? AND purpose = 'personal_memory'
              AND revoked_at IS NULL
            """,
            (user_id,),
        ).fetchone()

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
        if not isinstance(key, str) or not key.strip() or len(key) > 200:
            raise ValueError("Invalid memory key")
        if not isinstance(source, str) or not source.strip() or len(source) > 100:
            raise ValueError("Invalid memory source")
        validate_personal_payload(key)
        validate_personal_payload(source)
        if isinstance(confidence, bool) or not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between zero and one")
        validate_personal_payload(value)

        memory_id = str(uuid.uuid4())
        now = _utc_now()
        with self.database.transaction(immediate=True):
            consent = self._active_consent(user_id)
            if consent is None:
                raise PermissionError("Explicit memory consent is required")
            resolved_expiry = expires_at
            if resolved_expiry is not None:
                parsed_expiry = self._parse_timestamp(resolved_expiry)
                resolved_expiry = _utc_text(parsed_expiry)
            elif consent["retention_days"] is not None:
                resolved_expiry = _utc_text(
                    now + timedelta(days=consent["retention_days"])
                )
            self.database.connect().execute(
                """
                INSERT INTO memory_items (
                    id, user_id, memory_type, key, value_json, source,
                    confidence, status, expires_at, created_at, updated_at,
                    consent_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                """,
                (
                    memory_id,
                    user_id,
                    memory_type,
                    key.strip(),
                    json.dumps(value, ensure_ascii=False, allow_nan=False),
                    source.strip(),
                    confidence,
                    resolved_expiry,
                    _utc_text(now),
                    _utc_text(now),
                    consent["id"],
                ),
            )
        row = self.database.connect().execute(
            "SELECT * FROM memory_items WHERE id = ? AND user_id = ?",
            (memory_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Memory not found")
        return self._to_dict(row)

    def get(self, user_id: str, memory_id: str) -> dict:
        self._purge_expired_for_user(user_id)
        consent = self._active_consent(user_id)
        if consent is None:
            raise LookupError("Memory not found")
        row = self.database.connect().execute(
            """
            SELECT m.* FROM memory_items AS m
            WHERE m.id = ? AND m.user_id = ? AND m.consent_id = ?
              AND m.status = 'active'
            """,
            (memory_id, user_id, consent["id"]),
        ).fetchone()
        if row is None:
            raise LookupError("Memory not found")
        return self._to_dict(row)

    def list(self, user_id: str) -> tuple[dict, ...]:
        self._purge_expired_for_user(user_id)
        consent = self._active_consent(user_id)
        if consent is None:
            return ()
        rows = self.database.connect().execute(
            """
            SELECT m.* FROM memory_items AS m
            WHERE m.user_id = ? AND m.consent_id = ? AND m.status = 'active'
            ORDER BY m.updated_at DESC
            """,
            (user_id, consent["id"]),
        ).fetchall()
        return tuple(self._to_dict(row) for row in rows)

    def retrieve(
        self,
        user_id: str,
        *,
        query: str,
        limit: int = 5,
    ) -> tuple[dict[str, Any], ...]:
        if not isinstance(query, str) or not query.strip() or len(query) > 500:
            raise ValueError("Memory search query must contain 1 to 500 characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10:
            raise ValueError("Memory result limit must be between 1 and 10")
        query_terms = set(_TOKEN_PATTERN.findall(query.casefold()))
        if not query_terms:
            return ()
        ranked: list[tuple[float, str, dict[str, Any]]] = []
        for memory in self.list(user_id):
            searchable = " ".join((
                memory["memory_type"],
                memory["key"],
                json.dumps(memory["value"], ensure_ascii=False, sort_keys=True),
            )).casefold()
            terms = set(_TOKEN_PATTERN.findall(searchable))
            overlap = query_terms.intersection(terms)
            if not overlap:
                continue
            score = len(overlap) / len(query_terms)
            ranked.append((score, memory["updated_at"], memory))
        ranked.sort(key=lambda item: (-item[0], item[1], item[2]["id"]))
        return tuple({
            **memory,
            "relevance_score": round(score, 4),
        } for score, _updated_at, memory in ranked[:limit])

    def update(
        self,
        user_id: str,
        memory_id: str,
        *,
        value: object,
        confidence: float,
    ) -> dict:
        if isinstance(confidence, bool) or not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between zero and one")
        validate_personal_payload(value)
        self._purge_expired_for_user(user_id)
        with self.database.transaction(immediate=True):
            consent = self._active_consent(user_id)
            if consent is None:
                raise LookupError("Memory not found")
            cursor = self.database.connect().execute(
                """
                UPDATE memory_items
                SET value_json = ?, confidence = ?, updated_at = ?
                WHERE id = ? AND user_id = ? AND consent_id = ?
                  AND status = 'active'
                """,
                (
                    json.dumps(value, ensure_ascii=False, allow_nan=False),
                    confidence,
                    _utc_text(),
                    memory_id,
                    user_id,
                    consent["id"],
                ),
            )
            if cursor.rowcount != 1:
                raise LookupError("Memory not found")
        return self.get(user_id, memory_id)

    def delete(self, user_id: str, memory_id: str) -> bool:
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                "DELETE FROM memory_items WHERE id = ? AND user_id = ?",
                (memory_id, user_id),
            )
        return cursor.rowcount == 1

    def delete_all(self, user_id: str) -> int:
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                "DELETE FROM memory_items WHERE user_id = ?",
                (user_id,),
            )
        return cursor.rowcount

    def purge_expired(self) -> int:
        connection = self.database.connect()
        rows = connection.execute(
            "SELECT id, user_id, expires_at FROM memory_items "
            "WHERE expires_at IS NOT NULL"
        ).fetchall()
        expired = [
            (row["id"], row["user_id"])
            for row in rows
            if self._is_expired(row["expires_at"])
        ]
        if not expired:
            return 0
        with self.database.transaction(immediate=True):
            deleted = 0
            for memory_id, user_id in expired:
                cursor = self.database.connect().execute(
                    "DELETE FROM memory_items WHERE id = ? AND user_id = ?",
                    (memory_id, user_id),
                )
                deleted += cursor.rowcount
        return deleted

    def _purge_expired_for_user(self, user_id: str) -> int:
        rows = self.database.connect().execute(
            """
            SELECT id, expires_at FROM memory_items
            WHERE user_id = ? AND expires_at IS NOT NULL
            """,
            (user_id,),
        ).fetchall()
        expired = [
            row["id"] for row in rows if self._is_expired(row["expires_at"])
        ]
        if not expired:
            return 0
        with self.database.transaction(immediate=True):
            deleted = 0
            for memory_id in expired:
                cursor = self.database.connect().execute(
                    "DELETE FROM memory_items WHERE id = ? AND user_id = ?",
                    (memory_id, user_id),
                )
                deleted += cursor.rowcount
        return deleted

    def export(self, user_id: str) -> dict:
        return {
            "schema_version": 2,
            "user_id": user_id,
            "exported_at": _utc_text(),
            "consent": self.consent_status(user_id),
            "memories": list(self.list(user_id)),
        }

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
