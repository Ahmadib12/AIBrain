import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
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


def _write_transaction(database):
    dialect = getattr(database, "dialect", "sqlite")
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError("Unsupported persistence dialect")
    return database.transaction(immediate=dialect == "sqlite")


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
        with _write_transaction(self.database):
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
        with _write_transaction(self.database):
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
        with _write_transaction(self.database):
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
                        reason: str = "", *,
                        worker_id: str | None = None,
                        lease_token: str | None = None) -> dict:
        if target not in {"in_progress", "completed", "failed", "cancelled"}:
            raise ValueError("Unsupported task transition")
        if not isinstance(reason, str) or len(reason) > 500:
            raise ValueError("Task reason is too long")
        validate_personal_payload(reason)
        transitions = {
            "assigned": {"in_progress", "completed", "failed", "cancelled"},
            "in_progress": {"completed", "failed", "cancelled"},
        }
        with _write_transaction(self.database):
            task = self.get_task(user_id, task_id)
            if worker_id is not None or lease_token is not None:
                if not isinstance(worker_id, str) or not worker_id.strip():
                    raise PermissionError("Worker identity is required")
                if not isinstance(lease_token, str) or not lease_token.strip():
                    raise PermissionError("Current lease token is required")
                lock = (
                    " FOR UPDATE"
                    if getattr(self.database, "dialect", "sqlite") == "postgresql"
                    else ""
                )
                fenced = self.database.connect().execute(
                    """SELECT status,claimed_by,lease_token,lease_generation,
                              lease_expires_at,expires_at
                       FROM agent_tasks
                       WHERE id=? AND user_id=? AND agent_id=?""" + lock,
                    (task_id, user_id, task["agent_id"]),
                ).fetchone()
                if fenced is None:
                    raise LookupError("Task not found")
                if (
                    fenced["status"] != "in_progress"
                    or fenced["claimed_by"] != worker_id.strip()
                    or fenced["lease_token"] != lease_token.strip()
                ):
                    raise PermissionError("Worker lease is no longer current")
                if (
                    fenced["lease_expires_at"] is None
                    or datetime.fromisoformat(fenced["lease_expires_at"]) <= _now()
                    or datetime.fromisoformat(fenced["expires_at"]) <= _now()
                ):
                    raise PermissionError("Worker lease or task deadline has expired")
            current = task["status"]
            if target not in transitions.get(current, set()):
                raise ValueError("Invalid task transition")
            now = _stamp()
            details = {"from_status": current, "to_status": target}
            if reason.strip():
                details["reason"] = reason.strip()
            self._task_event(user_id, task_id, target, details)
            if worker_id is not None or lease_token is not None:
                cursor = self.database.connect().execute(
                    """UPDATE agent_tasks SET status=?,updated_at=?,
                       lease_token=NULL,lease_expires_at=NULL,heartbeat_at=NULL
                       WHERE id=? AND user_id=? AND agent_id=? AND status='in_progress'
                         AND claimed_by=? AND lease_token=?""",
                    (
                        target, now, task_id, user_id, task["agent_id"],
                        worker_id.strip(), lease_token.strip(),
                    ),
                )
                if cursor.rowcount != 1:
                    raise PermissionError("Worker lease changed before transition")
            else:
                self.database.connect().execute(
                    "UPDATE agent_tasks SET status=?,updated_at=? WHERE id=? AND user_id=?",
                    (target, now, task_id, user_id),
                )
            self._event(user_id, task["agent_id"], "task."+target, task_id, details)
        return self.get_task(user_id, task_id)

    def claim_task(
        self,
        user_id: str,
        agent_id: str,
        task_id: str,
        *,
        worker_id: str,
        lease_seconds: int = 300,
    ) -> dict:
        """Atomically claim an assigned task for one active worker."""
        if not isinstance(worker_id, str) or not 1 <= len(worker_id.strip()) <= 100:
            raise ValueError("Worker ID must contain 1 to 100 characters")
        validate_personal_payload(worker_id.strip())
        if not isinstance(lease_seconds, int) or not 30 <= lease_seconds <= 3600:
            raise ValueError("Lease seconds must be between 30 and 3600")

        dialect = getattr(self.database, "dialect", "sqlite")
        if dialect not in {"sqlite", "postgresql"}:
            raise RuntimeError("Unsupported persistence dialect")
        with self.database.transaction(immediate=dialect == "sqlite"):
            connection = self.database.connect()
            if dialect == "postgresql":
                owner = connection.execute(
                    "SELECT id FROM users WHERE id=? AND deleted_at IS NULL FOR UPDATE",
                    (user_id,),
                ).fetchone()
                if owner is None:
                    raise LookupError("Owner account not found")
                agent = connection.execute(
                    "SELECT id,status FROM agents WHERE id=? AND user_id=? FOR UPDATE",
                    (agent_id, user_id),
                ).fetchone()
                if agent is None:
                    raise LookupError("Agent not found")
                if agent["status"] != "active":
                    raise ValueError("Agent must be active")
                task_row = connection.execute(
                    """SELECT id,status,expires_at,claimed_by,lease_token,
                              lease_generation,lease_expires_at
                       FROM agent_tasks
                       WHERE id=? AND user_id=? AND agent_id=? FOR UPDATE""",
                    (task_id, user_id, agent_id),
                ).fetchone()
            else:
                self._agent(user_id, agent_id, active=True)
                task_row = connection.execute(
                    """SELECT id,status,expires_at,claimed_by,lease_token,
                              lease_generation,lease_expires_at
                       FROM agent_tasks
                       WHERE id=? AND user_id=? AND agent_id=?""",
                    (task_id, user_id, agent_id),
                ).fetchone()
            if task_row is None:
                raise LookupError("Task not found")
            expiry = datetime.fromisoformat(task_row["expires_at"])
            if expiry <= _now():
                raise ValueError("Task has expired")
            if task_row["status"] == "in_progress":
                if (
                    task_row["lease_expires_at"] is None
                    or datetime.fromisoformat(task_row["lease_expires_at"]) > _now()
                ):
                    raise ValueError("Task lease is still held")
                takeover_details = {
                    "from_status": "in_progress",
                    "to_status": "assigned",
                    "reason": "worker_lease_expired",
                    "previous_worker_id": task_row["claimed_by"],
                    "previous_lease_generation": task_row["lease_generation"],
                    "previous_lease_generation": task_row["lease_generation"],
                }
                self._task_event(
                    user_id, task_id, "requeued", takeover_details
                )
                cursor = connection.execute(
                    """UPDATE agent_tasks SET status='assigned',updated_at=?,
                       claimed_by=NULL,claimed_at=NULL,lease_token=NULL,
                       lease_expires_at=NULL,heartbeat_at=NULL
                       WHERE id=? AND user_id=? AND agent_id=? AND status='in_progress'
                         AND lease_token=?""",
                    (
                        _stamp(), task_id, user_id, agent_id,
                        task_row["lease_token"],
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError("Task lease changed during takeover")
                task_row = {
                    **dict(task_row),
                    "status": "assigned",
                }
            elif task_row["status"] != "assigned":
                raise ValueError("Task is no longer available to claim")

            now = _stamp()
            lease_token = str(uuid.uuid4())
            lease_generation = int(task_row["lease_generation"] or 0) + 1
            lease_expires_at = _stamp(
                _now() + timedelta(seconds=lease_seconds)
            )
            details = {
                "from_status": "assigned",
                "to_status": "in_progress",
                "worker_id": worker_id.strip(),
                "lease_expires_at": lease_expires_at,
                "lease_generation": lease_generation,
            }
            self._task_event(user_id, task_id, "in_progress", details)
            cursor = connection.execute(
                """UPDATE agent_tasks SET status='in_progress',updated_at=?,
                   claimed_by=?,claimed_at=?,lease_token=?,lease_generation=?,
                   lease_expires_at=?,heartbeat_at=?
                   WHERE id=? AND user_id=? AND agent_id=? AND status='assigned'""",
                (
                    now, worker_id.strip(), now, lease_token, lease_generation,
                    lease_expires_at, now,
                    task_id, user_id, agent_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Task claim conflicted with another worker")
            self._event(
                user_id,
                agent_id,
                "task.claimed",
                task_id,
                details,
            )
        return self.get_task(user_id, task_id)

    def heartbeat_task(
        self,
        user_id: str,
        agent_id: str,
        task_id: str,
        *,
        worker_id: str,
        lease_token: str,
        lease_seconds: int = 300,
    ) -> dict:
        """Renew only a worker's active, live task lease."""
        if not isinstance(worker_id, str) or not 1 <= len(worker_id.strip()) <= 100:
            raise ValueError("Worker ID must contain 1 to 100 characters")
        if not isinstance(lease_token, str) or not lease_token.strip():
            raise ValueError("Lease token must be provided")
        if not isinstance(lease_seconds, int) or not 30 <= lease_seconds <= 3600:
            raise ValueError("Lease seconds must be between 30 and 3600")

        with _write_transaction(self.database):
            connection = self.database.connect()
            lock = (
                " FOR UPDATE"
                if getattr(self.database, "dialect", "sqlite") == "postgresql"
                else ""
            )
            if getattr(self.database, "dialect", "sqlite") == "postgresql":
                connection.execute(
                    "SELECT id FROM users WHERE id=? AND deleted_at IS NULL FOR UPDATE",
                    (user_id,),
                ).fetchone()
                connection.execute(
                    "SELECT id,status FROM agents WHERE id=? AND user_id=? FOR UPDATE",
                    (agent_id, user_id),
                ).fetchone()
            task_row = connection.execute(
                """SELECT id,status,claimed_by,lease_token,lease_generation,
                          lease_expires_at,expires_at
                   FROM agent_tasks
                   WHERE id=? AND user_id=? AND agent_id=?""" + lock,
                (task_id, user_id, agent_id),
            ).fetchone()
            if task_row is None:
                raise LookupError("Task not found")
            if task_row["status"] != "in_progress":
                raise ValueError("Task is not in progress")
            if task_row["claimed_by"] != worker_id.strip():
                raise PermissionError("Worker does not own this task claim")
            if task_row["lease_token"] != lease_token.strip():
                raise PermissionError("Lease generation is no longer current")
            if datetime.fromisoformat(task_row["expires_at"]) <= _now():
                raise ValueError("Task has expired")
            if (
                task_row["lease_expires_at"] is not None
                and datetime.fromisoformat(task_row["lease_expires_at"]) <= _now()
            ):
                raise PermissionError("Task lease has expired")

            now = _stamp()
            lease_expires_at = _stamp(
                _now() + timedelta(seconds=lease_seconds)
            )
            cursor = connection.execute(
                """UPDATE agent_tasks SET heartbeat_at=?,lease_expires_at=?,updated_at=?
                   WHERE id=? AND user_id=? AND agent_id=? AND status='in_progress'
                     AND claimed_by=? AND lease_token=?""",
                (
                    now, lease_expires_at, now,
                    task_id, user_id, agent_id, worker_id.strip(),
                    lease_token.strip(),
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("Task heartbeat conflicted with its lease")
        return self.get_task(user_id, task_id)

    def reconcile_stale_task_claims(self, user_id: str | None = None) -> int:
        """Requeue claims whose worker lease expired; never execute again automatically."""
        now = _stamp()
        sql = """SELECT id,user_id,agent_id FROM agent_tasks
                 WHERE status='in_progress' AND lease_expires_at IS NOT NULL
                   AND lease_expires_at <= ?"""
        args: tuple = (now,)
        if user_id is not None:
            sql += " AND user_id=?"
            args = (now, user_id)
        rows = self.database.connect().execute(sql, args).fetchall()
        changed = 0
        for row in rows:
            try:
                with _write_transaction(self.database):
                    connection = self.database.connect()
                    lock = (
                        " FOR UPDATE"
                        if getattr(self.database, "dialect", "sqlite") == "postgresql"
                        else ""
                    )
                    task_row = connection.execute(
                        """SELECT id,status,lease_expires_at,claimed_by,
                                  lease_token,lease_generation
                           FROM agent_tasks
                           WHERE id=? AND user_id=? AND agent_id=?""" + lock,
                        (row["id"], row["user_id"], row["agent_id"]),
                    ).fetchone()
                    if (
                        task_row is None
                        or task_row["status"] != "in_progress"
                        or task_row["lease_expires_at"] is None
                        or datetime.fromisoformat(task_row["lease_expires_at"]) > _now()
                    ):
                        continue
                    details = {
                        "from_status": "in_progress",
                        "to_status": "assigned",
                        "reason": "worker_lease_expired",
                        "previous_worker_id": task_row["claimed_by"],
                    }
                    self._task_event(
                        row["user_id"], row["id"], "requeued", details
                    )
                    cursor = connection.execute(
                        """UPDATE agent_tasks SET status='assigned',updated_at=?,
                           claimed_by=NULL,claimed_at=NULL,
                           lease_token=NULL,lease_expires_at=NULL,heartbeat_at=NULL
                           WHERE id=? AND user_id=? AND agent_id=? AND status='in_progress'
                             AND lease_expires_at=?""",
                        (
                            now, row["id"], row["user_id"], row["agent_id"],
                            task_row["lease_expires_at"],
                        ),
                    )
                    if cursor.rowcount != 1:
                        continue
                    self._event(
                        row["user_id"], row["agent_id"],
                        "task.requeued", row["id"], details,
                    )
                    changed += 1
            except (ValueError, sqlite3.IntegrityError):
                continue
        return changed

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
        with _write_transaction(self.database):
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
        with _write_transaction(self.database):
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
