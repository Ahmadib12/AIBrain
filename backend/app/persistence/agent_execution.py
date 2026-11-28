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

from backend.app.persistence.contracts import DatabaseProtocol
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


def _write_transaction(database):
    dialect = getattr(database, "dialect", "sqlite")
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError("Unsupported persistence dialect")
    return database.transaction(immediate=dialect == "sqlite")


class AgentExecutionRepository:
    """Persist, authorize, and execute bounded read-only agent runs."""

    def __init__(self, database: DatabaseProtocol) -> None:
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
        with _write_transaction(self.database):
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

    def create_integration_run(
        self, user_id: str, task_id: str, actions: list[dict],
        integrations, connections,
    ) -> dict:
        """Persist an integration run with immutable per-step authority bindings.

        This creates and authorizes the plan only; execution is intentionally
        unavailable until the dedicated asynchronous M9 orchestrator is wired.
        """
        if not isinstance(actions, list) or not 1 <= len(actions) <= 10:
            raise ValueError("A run must contain between 1 and 10 actions")
        with _write_transaction(self.database):
            task = self._validate_live_task(user_id, task_id)
            ceiling = set(task["capability_ceiling"])
            normalized = []
            resolved_items = []
            for index, action in enumerate(actions):
                if not isinstance(action, dict) or set(action) - {
                    "tool_id", "arguments", "required_capability", "connection_id"
                }:
                    raise ValueError("Integration run action has unsupported fields")
                tool_id = action.get("tool_id")
                arguments = action.get("arguments", {})
                connection_id = action.get("connection_id")
                required = action.get("required_capability")
                if not isinstance(tool_id, str) or not tool_id.strip():
                    raise ValueError("Integration tool ID is invalid")
                if not isinstance(connection_id, str) or not connection_id.strip():
                    raise ValueError("Integration connection ID is required")
                if not isinstance(arguments, dict):
                    raise ValueError("Integration arguments must be an object")
                if required is not None and (
                    not isinstance(required, str) or required not in ceiling
                ):
                    raise PermissionError("Action exceeds the task capability ceiling")
                resolved = integrations.resolve_tool(tool_id)
                if resolved is None:
                    raise LookupError("Integration tool not found")
                integration_id, item = resolved
                contract = item.contract
                from backend.app.tools.contracts import ToolRisk
                if contract.risk is not ToolRisk.READ_ONLY:
                    raise PermissionError("Integration agent runs permit read-only tools only")
                validate_tool_arguments(contract.input_schema, arguments)
                if not connections.has_active_grants(
                    user_id, connection_id, integration_id, item.required_scopes
                ):
                    raise PermissionError("Active connection and exact owner-granted scopes are required")
                manifest = integrations.get(integration_id)
                if manifest is None:
                    raise LookupError("Integration manifest is unavailable")
                fingerprint = contract_fingerprint(contract)
                normalized.append({
                    "ordinal": index,
                    "tool_id": tool_id,
                    "arguments": arguments,
                    "required_capability": required,
                    "contract_fingerprint": fingerprint,
                    "integration_binding": {
                        "connection_id": connection_id,
                        "integration_id": integration_id,
                        "manifest_version": manifest.version,
                        "required_scopes": list(item.required_scopes),
                    },
                })
                resolved_items.append((integration_id, item, manifest, connection_id))
            required_caps = {
                item["required_capability"] for item in normalized
                if item["required_capability"] is not None
            }
            if not required_caps.issubset(
                self._effective_capabilities(user_id, task["agent_id"])
            ):
                raise PermissionError("Required agent capability is not currently granted")
            validate_personal_payload(normalized)
            now = _now()
            run_id = str(uuid.uuid4())
            expiry = min(
                datetime.fromisoformat(task["expires_at"]),
                now + timedelta(minutes=15),
            )
            actions_json = _canonical(normalized)
            plan_digest = _digest(normalized)
            self.database.connect().execute(
                """INSERT INTO agent_runs
                   (id,user_id,agent_id,task_id,actions_json,plan_digest,status,
                    expires_at,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,'proposed',?,?,?)""",
                (run_id, user_id, task["agent_id"], task_id, actions_json,
                 plan_digest, _stamp(expiry), _stamp(now), _stamp(now)),
            )
            for item, resolved in zip(normalized, resolved_items):
                step_id = str(uuid.uuid4())
                self.database.connect().execute(
                    """INSERT INTO agent_run_steps
                       (id,user_id,run_id,ordinal,tool_id,arguments_json,
                        contract_fingerprint,required_capability,status,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?, 'pending',?,?)""",
                    (step_id, user_id, run_id, item["ordinal"], item["tool_id"],
                     _canonical(item["arguments"]), item["contract_fingerprint"],
                     item["required_capability"], _stamp(now), _stamp(now)),
                )
                integration_id, tool, manifest, connection_id = resolved
                self.database.connect().execute(
                    """INSERT INTO agent_run_integration_bindings
                       (step_id,user_id,run_id,connection_id,integration_id,
                        manifest_version,tool_id,contract_fingerprint,
                        required_scopes_json,created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (step_id, user_id, run_id, connection_id, integration_id,
                     manifest.version, item["tool_id"], item["contract_fingerprint"],
                     _canonical(list(tool.required_scopes)), _stamp(now)),
                )
            self._event(user_id, run_id, "created", {
                "from_status": None, "to_status": "proposed",
                "step_count": len(normalized), "plan_digest": plan_digest,
                "integration_bound": True,
            })
        return self.get_run(user_id, run_id)

    def list_integration_bindings(self, user_id: str, run_id: str) -> list[dict]:
        self.get_run(user_id, run_id)
        rows = self.database.connect().execute(
            """SELECT step_id,connection_id,integration_id,manifest_version,
                      tool_id,contract_fingerprint,required_scopes_json,created_at
               FROM agent_run_integration_bindings
               WHERE user_id=? AND run_id=? ORDER BY step_id""",
            (user_id, run_id),
        ).fetchall()
        return [
            {**dict(row), "required_scopes": json.loads(row["required_scopes_json"])}
            for row in rows
        ]

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

    def _validate_integration_bindings(
        self, user_id: str, run: dict, integrations, connections,
    ) -> int:
        """Revalidate every durable integration binding against live authority."""
        actions = json.loads(run["actions_json"])
        expected = [
            (index, action) for index, action in enumerate(actions)
            if isinstance(action, dict) and "integration_binding" in action
        ]
        rows = self.database.connect().execute(
            """SELECT b.step_id,b.connection_id,b.integration_id,b.manifest_version,
                      b.tool_id,b.contract_fingerprint,b.required_scopes_json,
                      s.ordinal,s.tool_id AS step_tool_id,
                      s.contract_fingerprint AS step_fingerprint,s.arguments_json
               FROM agent_run_integration_bindings b
               JOIN agent_run_steps s ON s.id=b.step_id AND s.user_id=b.user_id
               WHERE b.user_id=? AND b.run_id=? ORDER BY s.ordinal""",
            (user_id, run["id"]),
        ).fetchall()
        if not expected and not rows:
            return 0
        if integrations is None or connections is None:
            raise PermissionError("Integration authority services are required")
        if len(rows) != len(expected):
            raise PermissionError("Integration run binding set is incomplete")
        if rows and len(expected) != len(actions):
            raise PermissionError("Mixed integration and non-integration runs are not permitted")
        by_ordinal = {ordinal: action for ordinal, action in expected}
        if len(by_ordinal) != len(expected):
            raise PermissionError("Integration run contains duplicate or invalid actions")
        for row in rows:
            binding = dict(row)
            action = by_ordinal.get(binding["ordinal"])
            if action is None:
                raise PermissionError("Integration step has no matching plan action")
            snapshot = action.get("integration_binding")
            if not isinstance(snapshot, dict):
                raise PermissionError("Integration plan binding is invalid")
            scopes = json.loads(binding["required_scopes_json"])
            if (
                action.get("tool_id") != binding["tool_id"]
                or binding["step_tool_id"] != binding["tool_id"]
                or binding["step_fingerprint"] != binding["contract_fingerprint"]
                or action.get("contract_fingerprint") != binding["contract_fingerprint"]
                or snapshot.get("connection_id") != binding["connection_id"]
                or snapshot.get("integration_id") != binding["integration_id"]
                or snapshot.get("manifest_version") != binding["manifest_version"]
                or snapshot.get("required_scopes") != scopes
            ):
                raise PermissionError("Persisted integration binding does not match the run plan")
            resolved = integrations.resolve_tool(binding["tool_id"])
            manifest = integrations.get(binding["integration_id"])
            if resolved is None or manifest is None:
                raise PermissionError("Bound integration is no longer registered")
            integration_id, tool = resolved
            current_fingerprint = contract_fingerprint(tool.contract)
            if (
                integration_id != binding["integration_id"]
                or manifest.version != binding["manifest_version"]
                or tool.contract.risk is not ToolRisk.READ_ONLY
                or current_fingerprint != binding["contract_fingerprint"]
                or tuple(tool.required_scopes) != tuple(scopes)
            ):
                raise PermissionError("Integration manifest or contract changed after binding")
            validate_tool_arguments(
                tool.contract.input_schema, json.loads(binding["arguments_json"])
            )
            if not connections.has_active_grants(
                user_id, binding["connection_id"], binding["integration_id"],
                tuple(scopes),
            ):
                raise PermissionError("Integration connection or required scopes are no longer active")
        return len(rows)

    def authorize_run(
        self, user_id: str, run_id: str, integrations=None, connections=None,
    ) -> dict:
        with _write_transaction(self.database):
            run = self._raw_run(user_id, run_id)
            if run["status"] != "proposed":
                raise ValueError("Only proposed runs can be authorized")
            self._authorize_or_execute_check(user_id, run)
            self._validate_integration_bindings(user_id, run, integrations, connections)
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
        lock = (
            " FOR UPDATE"
            if getattr(self.database, "dialect", "sqlite") == "postgresql"
            else ""
        )
        row = self.database.connect().execute(
            "SELECT * FROM agent_runs WHERE id=? AND user_id=?" + lock,
            (run_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Agent run not found")
        return dict(row)

    def execute_run(self, user_id: str, run_id: str,
                    gateway: ToolExecutionGateway, registry: ToolRegistry) -> dict:
        with _write_transaction(self.database):
            run = self._raw_run(user_id, run_id)
            if run["status"] != "authorized":
                raise ValueError("Run requires explicit owner authorization")
            bound = self.database.connect().execute(
                """SELECT 1 FROM agent_run_integration_bindings
                   WHERE user_id=? AND run_id=? LIMIT 1""",
                (user_id, run_id),
            ).fetchone()
            if bound is not None:
                raise PermissionError(
                    "Integration runs require the dedicated asynchronous orchestrator"
                )
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
            proposal = None
            try:
                # This transaction is the step authorization linearization point.
                # A later grant revocation cannot retroactively cancel a step
                # that was already authorized and durably marked as started.
                with _write_transaction(self.database):
                    run = self._raw_run(user_id, run_id)
                    if run["status"] != "running":
                        raise PermissionError("Agent run is no longer running")
                    self._authorize_or_execute_check(user_id, run)
                    current = registry.get(step["tool_id"])
                    if (
                        current is None
                        or current.risk is not ToolRisk.READ_ONLY
                        or contract_fingerprint(current) != step["contract_fingerprint"]
                    ):
                        raise PermissionError("Tool contract changed or is no longer read-only")
                    self._event(user_id, run_id, "step_started", {
                        "step_id": step["id"], "ordinal": step["ordinal"],
                        "tool_id": step["tool_id"],
                    })
                    self.database.connect().execute(
                        """UPDATE agent_run_steps SET status='running',updated_at=?
                           WHERE id=? AND user_id=? AND status='pending'""",
                        (_stamp(), step["id"], user_id),
                    )

                proposal = gateway.propose(
                    user_id, tool_id=step["tool_id"], arguments=step["arguments"]
                )
                persisted_request = gateway._tool_requests.get(user_id, proposal["id"])
                if persisted_request["contract_fingerprint"] != step["contract_fingerprint"]:
                    try:
                        gateway.cancel(user_id, proposal["id"])
                    except (LookupError, PermissionError):
                        pass
                    raise PermissionError("Tool contract changed while creating the tool request")
                result = gateway.execute(proposal, user_id=user_id)
                with _write_transaction(self.database):
                    self._event(user_id, run_id, "step_completed", {
                        "step_id": step["id"], "ordinal": step["ordinal"],
                        "tool_id": step["tool_id"], "tool_request_id": proposal["id"],
                    })
                    self.database.connect().execute(
                        """UPDATE agent_run_steps SET status='completed',
                           tool_request_id=?,result_json=?,updated_at=?
                           WHERE id=? AND user_id=? AND status='running'""",
                        (proposal["id"], _canonical(result), _stamp(),
                         step["id"], user_id),
                    )
            except Exception as exc:
                failed = True
                if proposal is not None:
                    try:
                        gateway.cancel(user_id, proposal["id"])
                    except (LookupError, PermissionError):
                        pass
                code = (
                    "authorization_or_contract_rejected"
                    if isinstance(exc, (PermissionError, LookupError, ValueError))
                    else "read_only_execution_failed"
                )
                with _write_transaction(self.database):
                    current_step = self.database.connect().execute(
                        "SELECT status FROM agent_run_steps WHERE id=? AND user_id=?",
                        (step["id"], user_id),
                    ).fetchone()
                    if current_step is not None and current_step["status"] in {"pending", "running"}:
                        self._event(user_id, run_id, "step_failed", {
                            "step_id": step["id"], "ordinal": step["ordinal"],
                            "error_code": code, "automatic_retry": False,
                        })
                        self.database.connect().execute(
                            """UPDATE agent_run_steps SET status='failed',error_code=?,
                               updated_at=? WHERE id=? AND user_id=? AND status=?""",
                            (code, _stamp(), step["id"], user_id, current_step["status"]),
                        )
                break

        with _write_transaction(self.database):
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
                pending_steps = self.database.connect().execute(
                    """SELECT id,ordinal FROM agent_run_steps
                       WHERE run_id=? AND user_id=? AND status='pending'
                       ORDER BY ordinal""",
                    (run_id, user_id),
                ).fetchall()
                for pending_step in pending_steps:
                    self._event(user_id, run_id, "step_skipped", {
                        "step_id": pending_step["id"],
                        "ordinal": pending_step["ordinal"],
                        "reason": "prior_step_failed",
                    })
                    self.database.connect().execute(
                        """UPDATE agent_run_steps SET status='skipped',updated_at=?
                           WHERE id=? AND user_id=? AND status='pending'""",
                        (now, pending_step["id"], user_id),
                    )
        return self.get_run(user_id, run_id)

    def cancel_run(self, user_id: str, run_id: str) -> dict:
        with _write_transaction(self.database):
            run = self._raw_run(user_id, run_id)
            if run["status"] not in {"proposed", "authorized", "running"}:
                raise ValueError("Only active uncompleted runs can be cancelled")
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
            with _write_transaction(self.database):
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

    def reconcile_stale_running_runs(
        self,
        *,
        stale_before: str,
        user_id: str | None = None,
    ) -> int:
        """Classify abandoned runs without replaying external actions."""
        sql = """SELECT id,user_id FROM agent_runs
                 WHERE status='running' AND updated_at <= ?"""
        args: tuple = (stale_before,)
        if user_id is not None:
            sql += " AND user_id=?"
            args = (stale_before, user_id)
        rows = self.database.connect().execute(sql, args).fetchall()
        recovered = 0
        for row in rows:
            with _write_transaction(self.database):
                run = self._raw_run(row["user_id"], row["id"])
                if run["status"] != "running":
                    continue
                if run["updated_at"] > stale_before:
                    continue
                steps = self.database.connect().execute(
                    """SELECT id,ordinal,status,tool_request_id
                       FROM agent_run_steps
                       WHERE user_id=? AND run_id=? ORDER BY ordinal""",
                    (row["user_id"], row["id"]),
                ).fetchall()
                running_or_dispatched = any(
                    step["status"] == "running"
                    or step["tool_request_id"] is not None
                    for step in steps
                )
                now = _stamp()
                code = (
                    "AGENT_PROCESS_INTERRUPTED_WITH_UNKNOWN_OUTCOME"
                    if running_or_dispatched
                    else "AGENT_PROCESS_INTERRUPTED_BEFORE_DISPATCH"
                )
                self._event(row["user_id"], row["id"], "reconciliation", {
                    "from_status": "running",
                    "to_status": "failed",
                    "error_code": code,
                    "automatic_retry": False,
                })
                cursor = self.database.connect().execute(
                    """UPDATE agent_runs SET status='failed',finished_at=?,updated_at=?
                       WHERE id=? AND user_id=? AND status='running'""",
                    (now, now, row["id"], row["user_id"]),
                )
                if cursor.rowcount != 1:
                    continue
                for step in steps:
                    if step["status"] not in {"pending", "running"}:
                        continue
                    event_type = (
                        "step_failed"
                        if step["status"] == "running"
                        else "step_skipped"
                    )
                    self._event(row["user_id"], row["id"], event_type, {
                        "step_id": step["id"],
                        "ordinal": step["ordinal"],
                        "error_code": code,
                        "automatic_retry": False,
                    })
                    target_status = (
                        "failed"
                        if step["status"] == "running"
                        else "skipped"
                    )
                    self.database.connect().execute(
                        """UPDATE agent_run_steps SET status=?,error_code=?,updated_at=?
                           WHERE id=? AND user_id=? AND status=?""",
                        (
                            target_status,
                            code,
                            now,
                            step["id"],
                            row["user_id"],
                            step["status"],
                        ),
                    )
                if not running_or_dispatched:
                    task_row = self.database.connect().execute(
                        """SELECT t.id,t.status,t.claimed_by,t.lease_token,
                                  t.lease_generation
                           FROM agent_tasks t
                           JOIN agent_runs r ON r.task_id=t.id
                           WHERE r.id=? AND r.user_id=? AND t.user_id=?""",
                        (row["id"], row["user_id"], row["user_id"]),
                    ).fetchone()
                    if task_row is not None and task_row["status"] == "in_progress":
                        requeue_details = {
                            "from_status": "in_progress",
                            "to_status": "assigned",
                            "reason": "run_reconciled_before_dispatch",
                            "previous_worker_id": task_row["claimed_by"],
                            "previous_lease_generation": task_row["lease_generation"],
                            "automatic_retry": False,
                        }
                        self.database.connect().execute(
                            """INSERT INTO agent_task_events
                               (id,user_id,task_id,actor_user_id,event_type,details_json,created_at)
                               VALUES (?,?,?,?,?,?,?)""",
                            (
                                str(uuid.uuid4()), row["user_id"], task_row["id"],
                                row["user_id"], "requeued",
                                _canonical(requeue_details), now,
                            ),
                        )
                        self.database.connect().execute(
                            """UPDATE agent_tasks SET status='assigned',updated_at=?,
                               claimed_by=NULL,claimed_at=NULL,lease_token=NULL,
                               lease_expires_at=NULL,heartbeat_at=NULL
                               WHERE id=? AND user_id=? AND status='in_progress'""",
                            (now, task_row["id"], row["user_id"]),
                        )
                recovered += 1
        return recovered
