"""Bridge validated plans into durable M9 proposals, never execution."""
from __future__ import annotations

from typing import Any, Protocol

from backend.app.intelligence.planning.engine import PlanningResult
from backend.app.persistence.agents import AgentRepository
from backend.app.persistence.agent_execution import AgentExecutionRepository
from backend.app.tools.registry import ToolRegistry


class PlanProposalRepository(Protocol):
    def create_run(
        self,
        user_id: str,
        task_id: str,
        actions: list[dict[str, Any]],
        registry: ToolRegistry,
    ) -> dict:
        ...


class PlanRunProposalBridge:
    """Translate explicitly mapped read-only plan tasks into an M9 run proposal.

    The bridge does not authorize, execute, grant capabilities, or accept
    model-generated tool names without a trusted task-to-tool mapping.
    """

    MAX_ACTIONS = 10

    def create_proposal(
        self,
        user_id: str,
        task_id: str,
        planning: PlanningResult,
        actions: list[dict[str, Any]],
        *,
        repository: AgentExecutionRepository | PlanProposalRepository,
        registry: ToolRegistry,
    ) -> dict:
        if not isinstance(planning, PlanningResult):
            raise TypeError("A validated PlanningResult is required")
        if (
            not planning.assessment.plan_valid
            or planning.assessment.requires_authorization
            or planning.assessment.requires_clarification
            or planning.assessment.missing_capabilities
            or planning.assessment.execution_permitted
        ):
            raise PermissionError("Planning assessment is not eligible for a run proposal")
        if not isinstance(actions, list) or not 1 <= len(actions) <= self.MAX_ACTIONS:
            raise ValueError("A plan proposal requires between 1 and 10 mapped actions")

        planned = {task.task_id: task for task in planning.plan.tasks}
        order = {task.task_id: index for index, task in enumerate(planning.plan.tasks)}
        mapped: set[str] = set()
        normalized: list[dict[str, Any]] = []
        last_order = -1
        for action in actions:
            if not isinstance(action, dict) or set(action) != {
                "plan_task_id", "tool_id", "arguments", "required_capability"
            }:
                raise ValueError("Plan action mapping has unsupported fields")
            plan_task_id = action["plan_task_id"]
            task = planned.get(plan_task_id)
            if task is None or task.capability_id is None:
                raise PermissionError("Action must map to a declared plan capability")
            if plan_task_id in mapped:
                raise ValueError("A planned task can be mapped only once")
            if order[plan_task_id] <= last_order:
                raise ValueError("Plan actions must preserve declared task order")
            if action["required_capability"] != task.capability_id:
                raise PermissionError("Action capability does not match the plan")
            if not isinstance(action["tool_id"], str) or not action["tool_id"].strip():
                raise ValueError("Mapped tool ID is invalid")
            if not isinstance(action["arguments"], dict):
                raise ValueError("Mapped tool arguments must be an object")
            mapped.add(plan_task_id)
            last_order = order[plan_task_id]
            normalized.append({
                "tool_id": action["tool_id"],
                "arguments": action["arguments"],
                "required_capability": task.capability_id,
            })

        expected = {
            task.task_id for task in planning.plan.tasks
            if task.capability_id is not None
        }
        if mapped != expected:
            raise PermissionError("Every capability-bearing plan task must be mapped exactly once")

        # AgentExecutionRepository independently validates live task authority,
        # task capability ceilings, READ_ONLY risk, schemas, and contract hashes.
        # Its result remains proposed until a separate owner authorization.
        return repository.create_run(user_id, task_id, normalized, registry)
