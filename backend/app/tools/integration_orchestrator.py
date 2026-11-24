"""Asynchronous, durable orchestrator for owner-bound read-only integrations.

The dispatch-start transaction is the no-retry boundary: once committed, any
missing provider response is recorded as outcome_unknown and is never retried.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from backend.app.persistence.agent_execution import AgentExecutionRepository
from backend.app.tools.contracts import ToolRisk, contract_fingerprint
from backend.app.tools.integration_runtime import ReadOnlyIntegrationRuntime
from backend.app.tools.validation import validate_tool_arguments


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class IntegrationAgentRunOrchestrator:
    """Execute only fully bound, explicitly authorized integration runs."""

    def __init__(
        self,
        *,
        execution: AgentExecutionRepository,
        runtime: ReadOnlyIntegrationRuntime,
    ) -> None:
        self.execution = execution
        self.runtime = runtime

    def _binding(self, user_id: str, run_id: str, step_id: str) -> dict:
        row = self.execution.database.connect().execute(
            """SELECT connection_id,integration_id,manifest_version,tool_id,
                      contract_fingerprint,required_scopes_json
               FROM agent_run_integration_bindings
               WHERE user_id=? AND run_id=? AND step_id=?""",
            (user_id, run_id, step_id),
        ).fetchone()
        if row is None:
            raise PermissionError("Integration step binding is missing")
        item = dict(row)
        item["required_scopes"] = json.loads(item.pop("required_scopes_json"))
        return item

    def _validate_step(self, user_id: str, run: dict, step: dict) -> dict:
        self.execution._authorize_or_execute_check(user_id, run)
        self.execution._validate_integration_bindings(
            user_id, run, self.runtime.manifests, self.runtime.connections
        )
        binding = self._binding(user_id, run["id"], step["id"])
        resolved = self.runtime.manifests.resolve_tool(step["tool_id"])
        if resolved is None:
            raise PermissionError("Bound integration tool is no longer registered")
        integration_id, item = resolved
        if (
            integration_id != binding["integration_id"]
            or item.contract.risk is not ToolRisk.READ_ONLY
            or contract_fingerprint(item.contract) != binding["contract_fingerprint"]
            or item.contract.tool_id != binding["tool_id"]
            or tuple(item.required_scopes) != tuple(binding["required_scopes"])
            or step["contract_fingerprint"] != binding["contract_fingerprint"]
        ):
            raise PermissionError("Integration contract changed before dispatch")
        validate_tool_arguments(item.contract.input_schema, step["arguments"])
        if self.runtime.adapters.get(integration_id) is None:
            raise PermissionError("No trusted adapter is registered for this integration")
        if not self.runtime.connections.has_active_grants(
            user_id, binding["connection_id"], integration_id,
            tuple(binding["required_scopes"]),
        ):
            raise PermissionError("Integration connection or scopes are no longer active")
        return binding

    async def execute_run(self, user_id: str, run_id: str) -> dict:
        """Execute a single integration run; duplicate/concurrent starts fail closed."""
        with self.execution.database.transaction(immediate=True):
            run = self.execution._raw_run(user_id, run_id)
            if run["status"] != "authorized":
                raise ValueError("Integration run requires explicit owner authorization")
            binding_count = self.execution.database.connect().execute(
                """SELECT COUNT(*) AS count FROM agent_run_integration_bindings
                   WHERE user_id=? AND run_id=?""",
                (user_id, run_id),
            ).fetchone()["count"]
            step_count = self.execution.database.connect().execute(
                """SELECT COUNT(*) AS count FROM agent_run_steps
                   WHERE user_id=? AND run_id=?""",
                (user_id, run_id),
            ).fetchone()["count"]
            if binding_count != step_count or step_count < 1:
                raise PermissionError("Only fully integration-bound runs can use this orchestrator")
            self.execution._authorize_or_execute_check(user_id, run)
            self.execution._validate_integration_bindings(
                user_id, run, self.runtime.manifests, self.runtime.connections
            )
            if datetime.fromisoformat(run["expires_at"]) <= datetime.now(timezone.utc):
                raise PermissionError("Integration run has expired")
            now = _stamp()
            self.execution._event(user_id, run_id, "started", {
                "from_status": "authorized", "to_status": "running",
                "plan_digest": run["plan_digest"], "integration_bound": True,
            })
            self.execution.database.connect().execute(
                """UPDATE agent_runs SET status='running',started_at=?,updated_at=?
                   WHERE id=? AND user_id=? AND status='authorized'""",
                (now, now, run_id, user_id),
            )

        failed = False
        for step in self.execution.list_steps(user_id, run_id):
            dispatch_started = False
            try:
                # Revalidate the owner, agent, task, manifest, contract, adapter,
                # and exact scopes inside the same write-locked transaction that
                # commits the durable dispatch-start boundary.
                with self.execution.database.transaction(immediate=True):
                    run = self.execution._raw_run(user_id, run_id)
                    if run["status"] != "running":
                        raise PermissionError("Integration run is no longer running")
                    if step["status"] != "pending":
                        raise ValueError("Integration step is not pending")
                    binding = self._validate_step(user_id, run, step)
                    now = _stamp()
                    self.execution._event(user_id, run_id, "step_started", {
                        "step_id": step["id"], "ordinal": step["ordinal"],
                        "tool_id": step["tool_id"],
                    })
                    self.execution.database.connect().execute(
                        """UPDATE agent_run_steps SET status='running',updated_at=?
                           WHERE id=? AND user_id=? AND status='pending'""",
                        (now, step["id"], user_id),
                    )
                    self.execution.database.connect().execute(
                        """INSERT INTO agent_run_integration_dispatches
                           (step_id,user_id,run_id,connection_id,integration_id,
                            tool_id,contract_fingerprint,status,created_at,updated_at)
                           VALUES (?,?,?,?,?,?,?,'prepared',?,?)""",
                        (step["id"], user_id, run_id, binding["connection_id"],
                         binding["integration_id"], binding["tool_id"],
                         binding["contract_fingerprint"], now, now),
                    )
                    self.execution._event(user_id, run_id, "integration_dispatch_started", {
                        "step_id": step["id"], "integration_id": binding["integration_id"],
                        "tool_id": binding["tool_id"],
                    })
                    self.execution.database.connect().execute(
                        """UPDATE agent_run_integration_dispatches
                           SET status='dispatch_started',dispatch_started_at=?,updated_at=?
                           WHERE step_id=? AND user_id=? AND status='prepared'""",
                        (now, now, step["id"], user_id),
                    )
                dispatch_started = True

                result = await self.runtime.execute(
                    user_id, binding["connection_id"], step["tool_id"],
                    step["arguments"],
                )
                encoded = json.dumps(
                    result, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False,
                )
                with self.execution.database.transaction(immediate=True):
                    now = _stamp()
                    self.execution._event(user_id, run_id, "integration_dispatch_succeeded", {
                        "step_id": step["id"], "integration_id": binding["integration_id"],
                    })
                    self.execution.database.connect().execute(
                        """UPDATE agent_run_integration_dispatches
                           SET status='succeeded',finished_at=?,outcome_json=?,updated_at=?
                           WHERE step_id=? AND user_id=? AND status='dispatch_started'""",
                        (now, encoded, now, step["id"], user_id),
                    )
                    self.execution._event(user_id, run_id, "step_completed", {
                        "step_id": step["id"], "ordinal": step["ordinal"],
                        "tool_id": step["tool_id"], "integration_id": binding["integration_id"],
                    })
                    self.execution.database.connect().execute(
                        """UPDATE agent_run_steps SET status='completed',
                           result_json=?,updated_at=?
                           WHERE id=? AND user_id=? AND status='running'""",
                        (encoded, now, step["id"], user_id),
                    )
            except asyncio.CancelledError:
                if dispatch_started:
                    self._record_unknown(user_id, run_id, step, "INTEGRATION_CANCELLED")
                else:
                    self._record_pre_dispatch_failure(user_id, run_id, step)
                self._finish_run(user_id, run_id, failed=True)
                raise
            except Exception:
                failed = True
                if dispatch_started:
                    self._record_unknown(user_id, run_id, step, "INTEGRATION_OUTCOME_UNKNOWN")
                else:
                    self._record_pre_dispatch_failure(user_id, run_id, step)
                break

        return self._finish_run(user_id, run_id, failed=failed)

    def _record_unknown(self, user_id: str, run_id: str, step: dict, code: str) -> None:
        with self.execution.database.transaction(immediate=True):
            now = _stamp()
            self.execution._event(user_id, run_id, "integration_dispatch_outcome_unknown", {
                "step_id": step["id"], "error_code": code, "automatic_retry": False,
            })
            self.execution.database.connect().execute(
                """UPDATE agent_run_integration_dispatches
                   SET status='outcome_unknown',finished_at=?,error_code=?,updated_at=?
                   WHERE step_id=? AND user_id=? AND status='dispatch_started'""",
                (now, code, now, step["id"], user_id),
            )
            self.execution._event(user_id, run_id, "step_failed", {
                "step_id": step["id"], "ordinal": step["ordinal"],
                "error_code": code, "automatic_retry": False,
            })
            self.execution.database.connect().execute(
                """UPDATE agent_run_steps SET status='failed',error_code=?,updated_at=?
                   WHERE id=? AND user_id=? AND status='running'""",
                (code, now, step["id"], user_id),
            )

    def _record_pre_dispatch_failure(self, user_id: str, run_id: str, step: dict) -> None:
        with self.execution.database.transaction(immediate=True):
            current = self.execution.database.connect().execute(
                "SELECT status FROM agent_run_steps WHERE id=? AND user_id=?",
                (step["id"], user_id),
            ).fetchone()
            if current is None or current["status"] not in {"pending", "running"}:
                return
            now = _stamp()
            code = "INTEGRATION_AUTHORITY_REJECTED"
            self.execution._event(user_id, run_id, "step_failed", {
                "step_id": step["id"], "ordinal": step["ordinal"],
                "error_code": code, "automatic_retry": False,
            })
            self.execution.database.connect().execute(
                """UPDATE agent_run_steps SET status='failed',error_code=?,updated_at=?
                   WHERE id=? AND user_id=? AND status=?""",
                (code, now, step["id"], user_id, current["status"]),
            )

    def recover_stale_dispatches(self, *, stale_before: str) -> int:
        """Fail closed on dispatches abandoned by a crashed process.

        A stale dispatch-started record is never replayed. The durable ledger is
        moved to outcome_unknown and its run is failed atomically.
        """
        candidates = self.execution.database.connect().execute(
            """SELECT step_id,user_id,run_id FROM agent_run_integration_dispatches
               WHERE status='dispatch_started' AND dispatch_started_at<=?
               ORDER BY dispatch_started_at,step_id""",
            (stale_before,),
        ).fetchall()
        recovered = 0
        for candidate in candidates:
            user_id = candidate["user_id"]
            run_id = candidate["run_id"]
            step_id = candidate["step_id"]
            with self.execution.database.transaction(immediate=True):
                dispatch = self.execution.database.connect().execute(
                    """SELECT status,dispatch_started_at FROM agent_run_integration_dispatches
                       WHERE step_id=? AND user_id=? AND run_id=?""",
                    (step_id, user_id, run_id),
                ).fetchone()
                if (
                    dispatch is None
                    or dispatch["status"] != "dispatch_started"
                    or dispatch["dispatch_started_at"] is None
                    or dispatch["dispatch_started_at"] > stale_before
                ):
                    continue
                step = self.execution.database.connect().execute(
                    """SELECT ordinal,tool_id,status FROM agent_run_steps
                       WHERE id=? AND user_id=? AND run_id=?""",
                    (step_id, user_id, run_id),
                ).fetchone()
                if step is None or step["status"] != "running":
                    continue
                now = _stamp()
                code = "INTEGRATION_PROCESS_INTERRUPTED"
                self.execution._event(user_id, run_id, "integration_dispatch_outcome_unknown", {
                    "step_id": step_id,
                    "error_code": code,
                    "automatic_retry": False,
                    "recovered_after_process_interruption": True,
                })
                cursor = self.execution.database.connect().execute(
                    """UPDATE agent_run_integration_dispatches
                       SET status='outcome_unknown',finished_at=?,error_code=?,updated_at=?
                       WHERE step_id=? AND user_id=? AND run_id=?
                         AND status='dispatch_started'""",
                    (now, code, now, step_id, user_id, run_id),
                )
                if cursor.rowcount != 1:
                    continue
                self.execution._event(user_id, run_id, "step_failed", {
                    "step_id": step_id,
                    "ordinal": step["ordinal"],
                    "error_code": code,
                    "automatic_retry": False,
                })
                self.execution.database.connect().execute(
                    """UPDATE agent_run_steps SET status='failed',error_code=?,updated_at=?
                       WHERE id=? AND user_id=? AND status='running'""",
                    (code, now, step_id, user_id),
                )
                run = self.execution._raw_run(user_id, run_id)
                if run["status"] == "running":
                    self.execution._event(user_id, run_id, "failed", {
                        "from_status": "running",
                        "to_status": "failed",
                        "reason": "integration_dispatch_interrupted",
                        "automatic_retry": False,
                        "integration_bound": True,
                    })
                    self.execution.database.connect().execute(
                        """UPDATE agent_runs SET status='failed',finished_at=?,updated_at=?
                           WHERE id=? AND user_id=? AND status='running'""",
                        (now, now, run_id, user_id),
                    )
                    pending = self.execution.database.connect().execute(
                        """SELECT id,ordinal FROM agent_run_steps
                           WHERE user_id=? AND run_id=? AND status='pending'
                           ORDER BY ordinal""",
                        (user_id, run_id),
                    ).fetchall()
                    for item in pending:
                        self.execution._event(user_id, run_id, "step_skipped", {
                            "step_id": item["id"],
                            "ordinal": item["ordinal"],
                            "reason": "prior_integration_dispatch_interrupted",
                        })
                        self.execution.database.connect().execute(
                            """UPDATE agent_run_steps SET status='skipped',updated_at=?
                               WHERE id=? AND user_id=? AND status='pending'""",
                            (now, item["id"], user_id),
                        )
                recovered += 1
        return recovered

    def _finish_run(self, user_id: str, run_id: str, *, failed: bool) -> dict:
        with self.execution.database.transaction(immediate=True):
            run = self.execution._raw_run(user_id, run_id)
            if run["status"] != "running":
                return self.execution.get_run(user_id, run_id)
            target = "failed" if failed else "completed"
            now = _stamp()
            self.execution._event(user_id, run_id, target, {
                "from_status": "running", "to_status": target,
                "automatic_retry": False, "integration_bound": True,
            })
            self.execution.database.connect().execute(
                """UPDATE agent_runs SET status=?,finished_at=?,updated_at=?
                   WHERE id=? AND user_id=? AND status='running'""",
                (target, now, now, run_id, user_id),
            )
            if failed:
                pending = self.execution.database.connect().execute(
                    """SELECT id,ordinal FROM agent_run_steps
                       WHERE user_id=? AND run_id=? AND status='pending'
                       ORDER BY ordinal""",
                    (user_id, run_id),
                ).fetchall()
                for item in pending:
                    self.execution._event(user_id, run_id, "step_skipped", {
                        "step_id": item["id"], "ordinal": item["ordinal"],
                        "reason": "prior_integration_step_failed",
                    })
                    self.execution.database.connect().execute(
                        """UPDATE agent_run_steps SET status='skipped',updated_at=?
                           WHERE id=? AND user_id=? AND status='pending'""",
                        (now, item["id"], user_id),
                    )
        return self.execution.get_run(user_id, run_id)
