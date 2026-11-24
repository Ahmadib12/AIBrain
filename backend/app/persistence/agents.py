import json
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.app.persistence.database import Database
from backend.app.persistence.validation import validate_personal_payload


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentRepository:
    """Owner-scoped persistence for registered agent identities.

    Registration creates a draft identity only. This repository does not
    execute agents, assign capabilities, or authorize tool access.
    """

    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _agent_from_row(row) -> dict[str, Any]:
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json"))
        return item

    def create(
        self,
        user_id: str,
        *,
        name: str,
        description: str = "",
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
            raise ValueError("Agent name must contain 1 to 100 characters")
        if not isinstance(description, str) or len(description) > 1000:
            raise ValueError("Agent description must not exceed 1000 characters")
        validate_personal_payload(name.strip())
        validate_personal_payload(description)
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError("Agent metadata must be an object")
        validate_personal_payload(metadata)

        agent_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = _utc_now()
        metadata_json = json.dumps(
            metadata,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            owner = connection.execute(
                "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
            if owner is None:
                raise LookupError("Owner account not found")
            connection.execute(
                """
                INSERT INTO agents (
                    id, user_id, name, description, metadata_json,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'draft', ?, ?)
                """,
                (
                    agent_id, user_id, name.strip(), description,
                    metadata_json, now, now,
                ),
            )
            connection.execute(
                """
                INSERT INTO agent_events (
                    id, user_id, agent_id, actor_user_id,
                    event_type, details_json, created_at
                ) VALUES (?, ?, ?, ?, 'registered', ?, ?)
                """,
                (
                    event_id, user_id, agent_id, user_id,
                    json.dumps(
                        {"initial_status": "draft"},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    now,
                ),
            )
        return self.get(user_id, agent_id)

    def list(self, user_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("Agent list limit must be between 1 and 100")
        rows = self.database.connect().execute(
            """
            SELECT id, user_id, name, description, metadata_json,
                   status, created_at, updated_at
            FROM agents
            WHERE user_id = ?
            ORDER BY created_at, id
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [self._agent_from_row(row) for row in rows]

    def get(self, user_id: str, agent_id: str) -> dict[str, Any]:
        row = self.database.connect().execute(
            """
            SELECT id, user_id, name, description, metadata_json,
                   status, created_at, updated_at
            FROM agents
            WHERE user_id = ? AND id = ?
            """,
            (user_id, agent_id),
        ).fetchone()
        if row is None:
            raise LookupError("Agent not found")
        return self._agent_from_row(row)

    def list_events(
        self,
        user_id: str,
        agent_id: str,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        # Confirm ownership before exposing the event stream.
        self.get(user_id, agent_id)
        rows = self.database.connect().execute(
            """
            SELECT id, user_id, agent_id, actor_user_id,
                   event_type, details_json, created_at
            FROM agent_events
            WHERE user_id = ? AND agent_id = ?
            ORDER BY created_at, id
            LIMIT ?
            """,
            (user_id, agent_id, limit),
        ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            events.append(item)
        return events

    def transition(
        self,
        user_id: str,
        agent_id: str,
        *,
        target_status: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Apply one explicit owner-requested lifecycle transition.

        A transition and its immutable event are committed atomically. Status
        changes never grant capabilities or authorize agent execution.
        """
        if target_status not in {"active", "suspended", "terminated"}:
            raise ValueError("Unsupported agent lifecycle target")
        if not isinstance(reason, str) or len(reason) > 500:
            raise ValueError("Lifecycle reason must not exceed 500 characters")
        validate_personal_payload(reason)

        transitions = {
            ("draft", "active"): "activated",
            ("draft", "terminated"): "terminated",
            ("active", "suspended"): "suspended",
            ("active", "terminated"): "terminated",
            ("suspended", "active"): "resumed",
            ("suspended", "terminated"): "terminated",
        }
        event_type = None
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT status FROM agents
                WHERE id = ? AND user_id = ?
                """,
                (agent_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("Agent not found")
            current_status = row["status"]
            event_type = transitions.get((current_status, target_status))
            if event_type is None:
                raise ValueError("Invalid agent lifecycle transition")

            details = {
                "from_status": current_status,
                "to_status": target_status,
            }
            if reason.strip():
                details["reason"] = reason.strip()
            connection.execute(
                """
                INSERT INTO agent_events (
                    id, user_id, agent_id, actor_user_id,
                    event_type, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    user_id,
                    agent_id,
                    user_id,
                    event_type,
                    json.dumps(
                        details,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ),
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE agents
                SET status = ?, updated_at = ?
                WHERE id = ? AND user_id = ? AND status = ?
                """,
                (target_status, now, agent_id, user_id, current_status),
            )
        return self.get(user_id, agent_id)
