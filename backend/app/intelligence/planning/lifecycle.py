"""Bounded planning lifecycle: refinement, composition, validation, and recovery advice.

All outputs are proposals. This module does not execute tasks, retry adapters,
grant permissions, or bypass the Phase 1 authorization lifecycle.
"""
from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.intelligence.planning.contracts import (
    GoalContract,
    PlannedTask,
    TaskPlanContract,
)


class RecoveryFailureKind(str, Enum):
    TRANSIENT = "transient"
    INVALID_OUTPUT = "invalid_output"
    MISSING_CAPABILITY = "missing_capability"
    AMBIGUOUS = "ambiguous"
    DEPENDENCY_FAILED = "dependency_failed"
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    RETRY_RECOMMENDED = "retry_recommended"
    REPLAN_RECOMMENDED = "replan_recommended"
    REQUEST_INPUT = "request_input"
    STOP = "stop"


class GoalRefinementResult(BaseModel):
    """A proposed goal revision; user confirmation is always separate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original_goal_id: str
    proposed_goal: GoalContract
    changed: bool
    requires_user_confirmation: bool = True


class PlanValidationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=300)
    task_id: str | None = Field(default=None, max_length=64)


class PlanValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    structurally_valid: bool
    capabilities_available: bool
    requires_clarification: bool
    issues: tuple[PlanValidationIssue, ...] = Field(default_factory=tuple, max_length=40)
    safe_to_propose: bool
    execution_permitted: bool = False

    @model_validator(mode="after")
    def enforce_advisory_boundary(self) -> "PlanValidationResult":
        if self.execution_permitted:
            raise ValueError("Plan validation cannot authorize execution")
        if self.safe_to_propose and (
            not self.structurally_valid
            or not self.capabilities_available
            or self.requires_clarification
        ):
            raise ValueError("A plan with blocking issues cannot be marked safe to propose")
        return self


class RecoveryRecommendation(BaseModel):
    """A recommendation for a human/orchestrator; never an automatic retry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    failed_task_id: str
    failure_kind: RecoveryFailureKind
    action: RecoveryAction
    rationale: str = Field(min_length=1, max_length=300)
    requires_user_input: bool
    execution_permitted: bool = False

    @model_validator(mode="after")
    def enforce_advisory_boundary(self) -> "RecoveryRecommendation":
        if self.execution_permitted:
            raise ValueError("Recovery advice cannot authorize execution")
        if self.action == RecoveryAction.REQUEST_INPUT and not self.requires_user_input:
            raise ValueError("Request-input recovery must require user input")
        return self


class PlanningLifecycle:
    """Provider-independent operations for improving and checking proposed plans."""

    def refine_goal(
        self,
        goal: GoalContract,
        *,
        description: str | None = None,
        success_criteria: Iterable[str] | None = None,
        constraints: Iterable[str] | None = None,
    ) -> GoalRefinementResult:
        """Apply only explicit refinements supplied by the caller."""
        GoalContract.model_validate(goal.model_dump())
        proposed = GoalContract.model_validate({
            "goal_id": goal.goal_id,
            "description": goal.description if description is None else description,
            "success_criteria": (
                goal.success_criteria
                if success_criteria is None
                else tuple(success_criteria)
            ),
            "constraints": (
                goal.constraints if constraints is None else tuple(constraints)
            ),
        })
        changed = proposed != goal
        return GoalRefinementResult(
            original_goal_id=goal.goal_id,
            proposed_goal=proposed,
            changed=changed,
            # Even a proposed refinement never implies user acceptance.
            requires_user_confirmation=True,
        )

    def extend_plan(
        self,
        plan: TaskPlanContract,
        additional_tasks: Iterable[PlannedTask],
    ) -> TaskPlanContract:
        """Append bounded steps while preserving dependency order and uniqueness."""
        TaskPlanContract.model_validate(plan.model_dump())
        additions = tuple(
            PlannedTask.model_validate(task.model_dump())
            for task in additional_tasks
        )
        combined = plan.tasks + additions
        if len(combined) > 20:
            raise ValueError("A plan cannot contain more than 20 tasks")
        return TaskPlanContract.model_validate({
            "plan_id": plan.plan_id,
            "goal": plan.goal.model_dump(),
            "tasks": [task.model_dump() for task in combined],
            "rationale": plan.rationale,
        })

    def validate_plan(
        self,
        plan: TaskPlanContract,
        *,
        available_capabilities: Iterable[str] = (),
        requires_clarification: bool = False,
    ) -> PlanValidationResult:
        """Check structure and capability readiness without authorizing execution."""
        issues: list[PlanValidationIssue] = []
        structurally_valid = True
        try:
            validated = TaskPlanContract.model_validate(plan.model_dump())
        except Exception:
            validated = None
            structurally_valid = False
            issues.append(PlanValidationIssue(
                code="invalid_structure",
                message="The proposed task graph failed structural validation",
            ))

        available = {
            value.strip().lower()
            for value in available_capabilities
            if isinstance(value, str) and value.strip()
        }
        referenced: dict[str, list[str]] = {}
        for task in (validated.tasks if validated is not None else ()):
            if task.capability_id is not None:
                referenced.setdefault(task.capability_id, []).append(task.task_id)
        missing = sorted(set(referenced) - available)
        for capability_id in missing:
            for task_id in referenced[capability_id]:
                issues.append(PlanValidationIssue(
                    code="missing_capability",
                    message=f"Required capability is unavailable: {capability_id}",
                    task_id=task_id,
                ))
        if requires_clarification:
            issues.append(PlanValidationIssue(
                code="clarification_required",
                message="Resolve the outstanding ambiguity before proceeding",
            ))
        capabilities_available = not missing
        safe = structurally_valid and capabilities_available and not requires_clarification
        return PlanValidationResult(
            structurally_valid=structurally_valid,
            capabilities_available=capabilities_available,
            requires_clarification=requires_clarification,
            issues=tuple(issues),
            safe_to_propose=safe,
            execution_permitted=False,
        )

    def recommend_recovery(
        self,
        plan: TaskPlanContract,
        *,
        failed_task_id: str,
        failure_kind: RecoveryFailureKind,
    ) -> RecoveryRecommendation:
        """Return a bounded next-step recommendation; never perform recovery."""
        validated = TaskPlanContract.model_validate(plan.model_dump())
        task_ids = {task.task_id for task in validated.tasks}
        if failed_task_id not in task_ids:
            raise ValueError("Failed task must belong to the supplied plan")

        recommendations = {
            RecoveryFailureKind.TRANSIENT: (
                RecoveryAction.RETRY_RECOMMENDED,
                "A transient failure may be retried only through the normal guarded executor.",
                False,
            ),
            RecoveryFailureKind.INVALID_OUTPUT: (
                RecoveryAction.REPLAN_RECOMMENDED,
                "Revise the proposed step and validate its output contract before another attempt.",
                False,
            ),
            RecoveryFailureKind.MISSING_CAPABILITY: (
                RecoveryAction.STOP,
                "Stop this path until the required capability is made available and checked.",
                False,
            ),
            RecoveryFailureKind.AMBIGUOUS: (
                RecoveryAction.REQUEST_INPUT,
                "Ask the user to resolve the ambiguity before creating a revised plan.",
                True,
            ),
            RecoveryFailureKind.DEPENDENCY_FAILED: (
                RecoveryAction.REPLAN_RECOMMENDED,
                "Reassess downstream dependencies and propose a revised task graph.",
                False,
            ),
            RecoveryFailureKind.UNKNOWN: (
                RecoveryAction.STOP,
                "Stop and investigate the failure; its outcome is not sufficiently understood.",
                False,
            ),
        }
        action, rationale, requires_input = recommendations[failure_kind]
        return RecoveryRecommendation(
            failed_task_id=failed_task_id,
            failure_kind=failure_kind,
            action=action,
            rationale=rationale,
            requires_user_input=requires_input,
            execution_permitted=False,
        )
