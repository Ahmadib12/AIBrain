"""Governed execution runs for owner-controlled agents.

Runs are explicit, digest-bound plans. Only registered READ_ONLY tools can be
executed in this milestone; state-changing and consequential tools remain
blocked by the existing authorization boundary.
"""
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.app.persistence.database import Database
from backend.app.persistence.validation import validate_personal_payload
from backend.app.tools.contracts import ToolRegistry, ToolRisk, contract_fingerprint
from backend.app.tools.runtime import ToolExecutionGateway
from backend.app.tools.validation import validate_tool_arguments


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _digest(actions: list[dict]) -> str:
    return hashlib.sha256(_canonical(actions).encode("utf-8")).hexdigest()


class AgentExecutionRepository:
    """Persist, authorize, and execute bounded read-only agent runs."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def _event(self, user_id: str, run_id: str, event_type: str,
               details: dict) -> None:
        self.database.connect().execute(
            """INSERT INTO agent_run_events
               (id,user_id,run_id,actor_user_id,event_type,details_json,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), user_id, run_id, user_id, event_type,
             _canonical(details), _stamp()),
        )

    def _get_task_context(self, user_id: str, task_id: str) -> dict:
        row = self.database.connect().execute(
            """SELECT t.*, a.status AS agent_status
               FROM agent_tasks t JOIN agents a ON a.id=t.agent_id
               WHERE t.id=? AND t.user_id=? AND a.user_id=?""",
            (task_id, user_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Agent task not found")
        item = dict(row)
        item["capability_ceiling"] = json.loads(item["capability_ceiling_json"])
        return item

    def _effective_capabilities(self, user_id: str, agent_id: str) -> set[str]:
        now = _stamp()
        rows = self.database.connect().execute(
            """SELECT DISTINCT g.capability FROM agent_capability_grants g
               WHERE g.user_id=? AND g.agent_id=?
                 AND (g.expires_at IS NULL OR g.expires_at > ?)
                 AND NOT EXISTS (SELECT 1 FROM agent_capability_revocations r
                                 WHERE r.grant_id=g.id)""",
            (user_id, agent_id, now),
        ).fetchall()
        return {row["capability"] for row in rows}

    def _validate_live_task(self, user_id: str, task_id: str) -> dict:
        task = self._get_task_context(user_id, task_id)
        if task["agent_status"] != "active":
            raise PermissionError("Agent is not active")
        if task["status"] not in {"assigned", "in_progress"}:
            raise PermissionError("Task is not executable")
        if datetime.fromisoformat(task["expires_at"]) <= _now():
            raise PermissionError("Task has expired")
        return task

    @staticmethod
    def _validate_actions(actions: list[dict], task: dict,
                          registry: ToolRegistry) -> list[dict]:
        if not isinstance(actions, list) or not 1 <= len(actions) <= 10:
            raise ValueError("A run must contain between 1 and 10 actions")
        ceiling = set(task["capability_ceiling"])
        normalized = []
        for index, action in enumerate(actions):
            if not isinstance(action, dict) or set(action) - {
                "tool_id", "arguments", "required_capability"
            }:
                raise ValueError("Run action has unsupported fields")
            tool_id = action.get("tool_id")
            arguments = action.get("arguments", {})
            required = action.get("required_capability")
            if not isinstance(tool_id, str) or not tool_id.strip():
                raise ValueError("Run action tool ID is invalid")
            if not isinstance(arguments, dict):
                raise ValueError("Run action arguments must be an object")
            if required is not None and (
                not isinstance(required, str) or required not in ceiling
            ):
                raise PermissionError("Action exceeds the task capability ceiling")
            contract = registry.get(tool_id)
            if contract is None:
                raise LookupError("Tool not found")
            if contract.risk is not ToolRisk.READ_ONLY:
                raise PermissionError(
                    "Agent runs currently support registered read-only tools only"
                )
            validate_tool_arguments(contract.input_schema, arguments)
            normalized.append({
                "ordinal": index,
                "tool_id": tool_id,
                "arguments": arguments,
                "required_capability": required,
                "contract_fingerprint": contract_fingerprint(contract),
            })
        validate_personal_payload(normalized)
        return normalized

    def create_run(self, user_id: str, task_id: str, actions: list[dict],
                   registry: ToolRegistry) -> dict:
        with self.database.transaction(immediate=True):
            task = self._validate_live_task(user_id, task_id)
            normalized = self._validate_actions(actions, task, registry)
            required = {
                item["required_capability"] for item in normalized
                if item["required_capability"] is not None
            }
            if not required.issubset(
                self._effective_capabilities(user_id, task["agent_id"])
            ):
                raise PermissionError("Required agent capability is not currently granted")
            now = _now()
            run_id = str(uuid.uuid4())
            expiry = min(
                datetime.fromisoformat(task["expires_at"]),
                now + timedelta(minutes=15),
            )
            actions_json = _canonical(normalized)
            self.database.connect().execute(
                """INSERT INTO agent_runs
                   (id,user_id,agent_id,task_id,actions_json,plan_digest,status,
                    expires_at,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,'proposed',?,?,?)""",
                (run_id, user_id, task["agent_id"], task_id, actions_json,
                 _digest(normalized), _stamp(expiry), _stamp(now), _stamp(now)),
            )
            for item in normalized:
                self.database.connect().execute(
                    """INSERT INTO agent_run_steps
                       (id,user_id,run_id,ordinal,tool_id,arguments_json,
                        contract_fingerprint,required_capability,status,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?, 'pending',?,?)""",
                    (str(uuid.uuid4()), user_id, run_id, item["ordinal"],
                     item["tool_id"], _canonical(item["arguments"]),
                     item["contract_fingerprint"], item["required_capability"],
                     _stamp(now), _stamp(now)),
                )
            self._event(user_id, run_id, "created", {
                "from_status": None, "to_status": "proposed",
                "step_count": len(normalized), "plan_digest": _digest(normalized),
            })
        return self.get_run(user_id, run_id)

    def get_run(self, user_id: str, run_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM agent_runs WHERE id=? AND user_id=?",
            (run_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Agent run not found")
        item = dict(row)
        item["actions"] = json.loads(item.pop("actions_json"))
        item["steps"] = self.list_steps(user_id, run_id)
        return item

    def list_steps(self, user_id: str, run_id: str) -> list[dict]:
        rows = self.database.connect().execute(
            """SELECT * FROM agent_run_steps
               WHERE user_id=? AND run_id=? ORDER BY ordinal""",
            (user_id, run_id),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["arguments"] = json.loads(item.pop("arguments_json"))
            raw = item.pop("result_json")
            item["result"] = json.loads(raw) if raw is not None else None
            result.append(item)
        return result

    def list_events(self, user_id: str, run_id: str, limit: int = 100) -> list[dict]:
        self.get_run(user_id, run_id)
        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100")
        rows = self.database.connect().execute(
            """SELECT * FROM agent_run_events WHERE user_id=? AND run_id=?
               ORDER BY created_at,id LIMIT ?""",
            (user_id, run_id, limit),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result

    def _authorize_or_execute_check(self, user_id: str, run: dict) -> dict:
        task = self._validate_live_task(user_id, run["task_id"])
        if task["agent_id"] != run["agent_id"]:
            raise PermissionError("Run agent binding changed")
        actions = json.loads(run["actions_json"])
        if _digest(actions) != run["plan_digest"]:
            raise PermissionError("Run plan digest mismatch")
        required = {
            item["required_capability"] for item in actions
            if item["required_capability"] is not None
        }
        if not required.issubset(
            self._effective_capabilities(user_id, run["agent_id"])
        ):
            raise PermissionError("Required agent capability is no longer granted")
        return task

    def authorize_run(self, user_id: str, run_id: str) -> dict:
        with self.database.transaction(immediate=True):
            run = self._raw_run(user_id, run_id)
            if run["status"] != "proposed":
                raise ValueError("Only proposed runs can be authorized")
            self._authorize_or_execute_check(user_id, run)
            if datetime.fromisoformat(run["expires_at"]) <= _now():
                raise PermissionError("Run authorization has expired")
            now = _stamp()
            self._event(user_id, run_id, "authorized", {
                "from_status": "proposed", "to_status": "authorized",
                "plan_digest": run["plan_digest"],
            })
            self.database.connect().execute(
                """UPDATE agent_runs SET status='authorized',authorized_at=?,
                   updated_at=? WHERE id=? AND user_id=? AND status='proposed'""",
                (now, now, run_id, user_id),
            )
        return self.get_run(user_id, run_id)

    def _raw_run(self, user_id: str, run_id: str):
        row = self.database.connect().execute(
            "SELECT * FROM agent_runs WHERE id=? AND user_id=?",
            (run_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Agent run not found")
        return dict(row)

    def execute_run(self, user_id: str, run_id: str,
                    gateway: ToolExecutionGateway, registry: ToolRegistry) -> dict:
        with self.database.transaction(immediate=True):
            run = self._raw_run(user_id, run_id)
            if run["status"] != "authorized":
                raise ValueError("Run requires explicit owner authorization")
            self._authorize_or_execute_check(user_id, run)
            if datetime.fromisoformat(run["expires_at"]) <= _now():
                raise PermissionError("Run has expired")
            now = _stamp()
            self._event(user_id, run_id, "started", {
                "from_status": "authorized", "to_status": "running",
                "plan_digest": run["plan_digest"],
            })
            self.database.connect().execute(
                """UPDATE agent_runs SET status='running',started_at=?,updated_at=?
                   WHERE id=? AND user_id=? AND status='authorized'""",
                (now, now, run_id, user_id),
            )

        failed = False
        for step in self.list_steps(user_id, run_id):
            try:
                current = registry.get(step["tool_id"])
                if (
                    current is None
                    or current.risk is not ToolRisk.READ_ONLY
                    or contract_fingerprint(current) != step["contract_fingerprint"]
                ):
                    raise PermissionError("Tool contract changed or is no longer read-only")
                if step["required_capability"] is not None:
                    task = self._validate_live_task(user_id, self._raw_run(user_id, run_id)["task_id"])
                    if step["required_capability"] not in self._effective_capabilities(user_id, task["agent_id"]):
                        raise PermissionError("Required agent capability was revoked")
                proposal = gateway.propose(
                    user_id, tool_id=step["tool_id"], arguments=step["arguments"]
                )
                result = gateway.execute(proposal, user_id=user_id)
                with self.database.transaction(immediate=True):
                    self.database.connect().execute(
                        """UPDATE agent_run_steps SET status='completed',
                           tool_request_id=?,result_json=?,updated_at=?
                           WHERE id=? AND user_id=? AND status='pending'""",
                        (proposal["id"], _canonical(result), _stamp(),
                         step["id"], user_id),
                    )
                    self._event(user_id, run_id, "step_completed", {
                        "step_id": step["id"], "ordinal": step["ordinal"],
                        "tool_id": step["tool_id"], "tool_request_id": proposal["id"],
                    })
            except Exception as exc:
                failed = True
                code = (
                    "authorization_or_contract_rejected"
                    if isinstance(exc, (PermissionError, LookupError, ValueError))
                    else "read_only_execution_failed"
                )
                with self.database.transaction(immediate=True):
                    self.database.connect().execute(
                        """UPDATE agent_run_steps SET status='failed',error_code=?,
                           updated_at=? WHERE id=? AND user_id=? AND status='pending'""",
                        (code, _stamp(), step["id"], user_id),
                    )
                    self._event(user_id, run_id, "step_failed", {
                        "step_id": step["id"], "ordinal": step["ordinal"],
                        "error_code": code, "automatic_retry": False,
                    })
                break

        with self.database.transaction(immediate=True):
            run = self._raw_run(user_id, run_id)
            target = "failed" if failed else "completed"
            now = _stamp()
            self._event(user_id, run_id, target, {
                "from_status": "running", "to_status": target,
                "automatic_retry": False,
            })
            self.database.connect().execute(
                """UPDATE agent_runs SET status=?,finished_at=?,updated_at=?
                   WHERE id=? AND user_id=? AND status='running'""",
                (target, now, now, run_id, user_id),
            )
            if failed:
                self.database.connect().execute(
                    """UPDATE agent_run_steps SET status='skipped',updated_at=?
                       WHERE run_id=? AND user_id=? AND status='pending'""",
                    (now, run_id, user_id),
                )
        return self.get_run(user_id, run_id)

    def cancel_run(self, user_id: str, run_id: str) -> dict:
        with self.database.transaction(immediate=True):
            run = self._raw_run(user_id, run_id)
            if run["status"] not in {"proposed", "authorized"}:
                raise ValueError("Only unstarted runs can be cancelled")
            now = _stamp()
            self._event(user_id, run_id, "cancelled", {
                "from_status": run["status"], "to_status": "cancelled",
            })
            self.database.connect().execute(
                """UPDATE agent_runs SET status='cancelled',finished_at=?,updated_at=?
                   WHERE id=? AND user_id=?""",
                (now, now, run_id, user_id),
            )
        return self.get_run(user_id, run_id)

    def reconcile_expired_runs(self, user_id: str) -> int:
        now = _stamp()
        rows = self.database.connect().execute(
            """SELECT id FROM agent_runs WHERE user_id=?
               AND status IN ('proposed','authorized') AND expires_at <= ?""",
            (user_id, now),
        ).fetchall()
        changed = 0
        for row in rows:
            with self.database.transaction(immediate=True):
                run = self._raw_run(user_id, row["id"])
                if run["status"] not in {"proposed", "authorized"}:
                    continue
                if run["expires_at"] > now:
                    continue
                self._event(user_id, run["id"], "expired", {
                    "from_status": run["status"], "to_status": "expired",
                    "reason": "run_deadline_elapsed",
                })
                self.database.connect().execute(
                    """UPDATE agent_runs SET status='expired',finished_at=?,updated_at=?
                       WHERE id=? AND user_id=? AND status=?""",
                    (now, now, run["id"], user_id, run["status"]),
                )
                changed += 1
        return changed
