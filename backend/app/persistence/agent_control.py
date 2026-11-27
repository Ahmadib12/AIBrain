import json
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.app.persistence.contracts import DatabaseProtocol
from backend.app.persistence.validation import validate_personal_payload


CAPABILITY_CATALOG_VERSION = 1

CAPABILITIES = frozenset({
    # Internal assistant capability used by bounded planning and local generation.
    "text_generation",
    "research.read",
    "notes.read",
    "notes.write",
    "calendar.read",
    "calendar.write",
    "web.search",
    "files.read",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    )


class AgentControlRepository:
    """Owner-controlled agent grants, task records, messages and recovery.

    This is a control-plane ledger only. It never invokes a provider, tool,
    executor, device, or agent runtime.
    """

    def __init__(self, database: DatabaseProtocol) -> None:
        self.database = database

    def _agent(self, user_id: str, agent_id: str, *, active: bool = False):
        sql = "SELECT id, status FROM agents WHERE id=? AND user_id=?"
        row = self.database.connect().execute(sql, (agent_id, user_id)).fetchone()
        if row is None:
            raise LookupError("Agent not found")
        if active and row["status"] != "active":
            raise ValueError("Agent must be active")
        return row

    def _event(self, user_id: str, agent_id: str, event_type: str,
               subject_id: str, details: dict) -> None:
        self.database.connect().execute(
            """INSERT INTO agent_control_events
               (id,user_id,agent_id,event_type,subject_id,details_json,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), user_id, agent_id, event_type,
             subject_id, _json(details), _stamp()),
        )

    @staticmethod
    def _grant(row) -> dict:
        return dict(row)

    def grant(self, user_id: str, agent_id: str, capability: str,
              expires_at: str | None = None) -> dict:
        if capability not in CAPABILITIES:
            raise ValueError("Unknown capability")
        now = _now()
        if expires_at is not None:
            try:
                expiry = datetime.fromisoformat(expires_at)
                if expiry.tzinfo is None or expiry <= now:
                    raise ValueError
                expires_at = expiry.astimezone(timezone.utc).isoformat()
            except (TypeError, ValueError):
                raise ValueError("Expiry must be a future timezone-aware ISO timestamp") from None
        grant_id = str(uuid.uuid4())
        with self.database.transaction(immediate=True):
            self._agent(user_id, agent_id, active=True)
            connection = self.database.connect()
            connection.execute(
                """INSERT INTO agent_capability_grants
                   (id,user_id,agent_id,capability,expires_at,created_at)
                   VALUES (?,?,?,?,?,?)""",
                (grant_id, user_id, agent_id, capability, expires_at, _stamp(now)),
            )
            self._event(user_id, agent_id, "capability.granted", grant_id,
                        {"capability": capability, "expires_at": expires_at})
        return self.get_grant(user_id, agent_id, grant_id)

    def get_grant(self, user_id: str, agent_id: str, grant_id: str) -> dict:
        row = self.database.connect().execute(
            """SELECT g.*,
                 EXISTS(SELECT 1 FROM agent_capability_revocations r
                        WHERE r.grant_id=g.id) AS revoked
               FROM agent_capability_grants g
               WHERE g.user_id=? AND g.agent_id=? AND g.id=?""",
            (user_id, agent_id, grant_id),
        ).fetchone()
        if row is None:
            raise LookupError("Grant not found")
        return dict(row)

    def list_grants(self, user_id: str, agent_id: str) -> list[dict]:
        self._agent(user_id, agent_id)
        rows = self.database.connect().execute(
            """SELECT g.*,
                 EXISTS(SELECT 1 FROM agent_capability_revocations r
                        WHERE r.grant_id=g.id) AS revoked
               FROM agent_capability_grants g
               WHERE g.user_id=? AND g.agent_id=? ORDER BY g.created_at,g.id""",
            (user_id, agent_id),
        ).fetchall()
        return [dict(row) for row in rows]

    def revoke(self, user_id: str, agent_id: str, grant_id: str,
               reason: str = "") -> dict:
        if not isinstance(reason, str) or len(reason) > 500:
            raise ValueError("Revocation reason is too long")
        validate_personal_payload(reason)
        with self.database.transaction(immediate=True):
            grant = self.get_grant(user_id, agent_id, grant_id)
            if grant["revoked"]:
                raise ValueError("Grant already revoked")
            self.database.connect().execute(
                """INSERT INTO agent_capability_revocations
                   (id,user_id,grant_id,reason,created_at) VALUES (?,?,?,?,?)""",
                (str(uuid.uuid4()), user_id, grant_id, reason.strip(), _stamp()),
            )
            self._event(user_id, agent_id, "capability.revoked", grant_id,
                        {"capability": grant["capability"], "reason": reason.strip()})
        return self.get_grant(user_id, agent_id, grant_id)

    def _effective_capabilities(self, user_id: str, agent_id: str, now: str) -> set[str]:
        rows = self.database.connect().execute(
            """SELECT DISTINCT g.capability FROM agent_capability_grants g
               WHERE g.user_id=? AND g.agent_id=?
                 AND (g.expires_at IS NULL OR g.expires_at > ?)
                 AND NOT EXISTS (SELECT 1 FROM agent_capability_revocations r
                                 WHERE r.grant_id=g.id)""",
            (user_id, agent_id, now),
        ).fetchall()
        return {row["capability"] for row in rows}

    def create_task(self, user_id: str, agent_id: str, *, title: str,
                    goal: str, context: dict, capability_ceiling: list[str],
                    expires_at: str) -> dict:
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 160:
            raise ValueError("Task title must contain 1 to 160 characters")
        if not isinstance(goal, str) or len(goal) > 4000:
            raise ValueError("Task goal is too long")
        if not isinstance(context, dict) or not isinstance(capability_ceiling, list):
            raise ValueError("Task context and capability ceiling have invalid types")
        if len(set(capability_ceiling)) != len(capability_ceiling):
            raise ValueError("Duplicate capabilities are not allowed")
        if any(not isinstance(item, str) or item not in CAPABILITIES for item in capability_ceiling):
            raise ValueError("Unknown capability in task ceiling")
        validate_personal_payload({"title": title, "goal": goal, "context": context})
        now = _now()
        try:
            expiry = datetime.fromisoformat(expires_at)
            if expiry.tzinfo is None or expiry <= now:
                raise ValueError
            expires_at = expiry.astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError):
            raise ValueError("Task expiry must be a future timezone-aware ISO timestamp") from None
        task_id = str(uuid.uuid4())
        with self.database.transaction(immediate=True):
            self._agent(user_id, agent_id, active=True)
            allowed = self._effective_capabilities(user_id, agent_id, _stamp(now))
            if not set(capability_ceiling).issubset(allowed):
                raise ValueError("Task capability ceiling exceeds active grants")
            connection = self.database.connect()
            connection.execute(
                """INSERT INTO agent_tasks
                   (id,user_id,agent_id,title,goal,context_json,
                    capability_ceiling_json,status,expires_at,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,'assigned',?,?,?)""",
                (task_id,user_id,agent_id,title.strip(),goal,_json(context),
                 _json(capability_ceiling),expires_at,_stamp(now),_stamp(now)),
            )
            self._task_event(user_id, task_id, "assigned",
                             {"from_status": None, "to_status": "assigned"})
            self._event(user_id, agent_id, "task.assigned", task_id,
                        {"capability_ceiling": capability_ceiling, "expires_at": expires_at})
        return self.get_task(user_id, task_id)

    def _task_event(self, user_id: str, task_id: str, event_type: str,
                    details: dict) -> None:
        self.database.connect().execute(
            """INSERT INTO agent_task_events
               (id,user_id,task_id,actor_user_id,event_type,details_json,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), user_id, task_id, user_id, event_type,
             _json(details), _stamp()),
        )

    @staticmethod
    def _task(row) -> dict:
        item = dict(row)
        item["context"] = json.loads(item.pop("context_json"))
        item["capability_ceiling"] = json.loads(item.pop("capability_ceiling_json"))
        return item

    def get_task(self, user_id: str, task_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM agent_tasks WHERE id=? AND user_id=?",
            (task_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Task not found")
        return self._task(row)

    def list_tasks(self, user_id: str, agent_id: str, limit: int = 100) -> list[dict]:
        self._agent(user_id, agent_id)
        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100")
        rows = self.database.connect().execute(
            """SELECT * FROM agent_tasks WHERE user_id=? AND agent_id=?
               ORDER BY created_at,id LIMIT ?""",
            (user_id, agent_id, limit),
        ).fetchall()
        return [self._task(row) for row in rows]

    def transition_task(self, user_id: str, task_id: str, target: str,
                        reason: str = "") -> dict:
        if target not in {"in_progress", "completed", "failed", "cancelled"}:
            raise ValueError("Unsupported task transition")
        if not isinstance(reason, str) or len(reason) > 500:
            raise ValueError("Task reason is too long")
        validate_personal_payload(reason)
        transitions = {
            "assigned": {"in_progress", "completed", "failed", "cancelled"},
            "in_progress": {"completed", "failed", "cancelled"},
        }
        with self.database.transaction(immediate=True):
            task = self.get_task(user_id, task_id)
            current = task["status"]
            if target not in transitions.get(current, set()):
                raise ValueError("Invalid task transition")
            now = _stamp()
            details = {"from_status": current, "to_status": target}
            if reason.strip():
                details["reason"] = reason.strip()
            self._task_event(user_id, task_id, target, details)
            self.database.connect().execute(
                "UPDATE agent_tasks SET status=?,updated_at=? WHERE id=? AND user_id=?",
                (target, now, task_id, user_id),
            )
            self._event(user_id, task["agent_id"], "task."+target, task_id, details)
        return self.get_task(user_id, task_id)

    def reconcile_expired_tasks(self, user_id: str | None = None) -> int:
        now = _stamp()
        sql = """SELECT id,user_id FROM agent_tasks
                 WHERE status IN ('assigned','in_progress') AND expires_at <= ?"""
        args: tuple = (now,)
        if user_id is not None:
            sql += " AND user_id=?"
            args = (now, user_id)
        rows = self.database.connect().execute(sql, args).fetchall()
        changed = 0
        for row in rows:
            try:
                self._expire_task(row["user_id"], row["id"])
                changed += 1
            except ValueError:
                continue
        return changed

    def _expire_task(self, user_id: str, task_id: str) -> None:
        with self.database.transaction(immediate=True):
            task = self.get_task(user_id, task_id)
            if task["status"] not in {"assigned", "in_progress"}:
                raise ValueError("Task is no longer expirable")
            details = {"from_status": task["status"], "to_status": "expired",
                       "reason": "deadline_elapsed"}
            self._task_event(user_id, task_id, "expired", details)
            self.database.connect().execute(
                "UPDATE agent_tasks SET status='expired',updated_at=? WHERE id=?",
                (_stamp(), task_id),
            )
            self._event(user_id, task["agent_id"], "task.expired", task_id, details)

    def send_message(self, user_id: str, sender_agent_id: str,
                     recipient_agent_id: str, payload: dict,
                     task_id: str | None = None) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Message payload must be an object")
        validate_personal_payload(payload)
        message_id = str(uuid.uuid4())
        with self.database.transaction(immediate=True):
            self._agent(user_id, sender_agent_id, active=True)
            self._agent(user_id, recipient_agent_id, active=True)
            if task_id is not None:
                task = self.get_task(user_id, task_id)
                if task["agent_id"] != recipient_agent_id:
                    raise ValueError("Task is not assigned to recipient")
            self.database.connect().execute(
                """INSERT INTO agent_messages
                   (id,user_id,sender_agent_id,recipient_agent_id,task_id,payload_json,created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (message_id,user_id,sender_agent_id,recipient_agent_id,
                 task_id,_json(payload),_stamp()),
            )
            self._event(user_id, sender_agent_id, "message.sent", message_id,
                        {"recipient_agent_id": recipient_agent_id, "task_id": task_id})
        return self.get_message(user_id, message_id)

    @staticmethod
    def _message(row) -> dict:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        return item

    def get_message(self, user_id: str, message_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM agent_messages WHERE id=? AND user_id=?",
            (message_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Message not found")
        return self._message(row)


    def list_task_events(self, user_id: str, task_id: str, limit: int = 100) -> list[dict]:
        self.get_task(user_id, task_id)
        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100")
        rows = self.database.connect().execute(
            """SELECT * FROM agent_task_events
               WHERE user_id=? AND task_id=? ORDER BY created_at,id LIMIT ?""",
            (user_id, task_id, limit),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result

    def list_messages(self, user_id: str, agent_id: str, limit: int = 100) -> list[dict]:
        self._agent(user_id, agent_id)
        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100")
        rows = self.database.connect().execute(
            """SELECT * FROM agent_messages
               WHERE user_id=? AND recipient_agent_id=?
               ORDER BY created_at,id LIMIT ?""",
            (user_id,agent_id,limit),
        ).fetchall()
        return [self._message(row) for row in rows]

    def list_events(self, user_id: str, agent_id: str, limit: int = 100) -> list[dict]:
        self._agent(user_id, agent_id)
        rows = self.database.connect().execute(
            """SELECT * FROM agent_control_events
               WHERE user_id=? AND agent_id=? ORDER BY created_at,id LIMIT ?""",
            (user_id,agent_id,limit),
        ).fetchall()
        result=[]
        for row in rows:
            item=dict(row)
            item["details"]=json.loads(item.pop("details_json"))
            result.append(item)
        return result
