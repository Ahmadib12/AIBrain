"""Deterministic intent-to-plan pipeline.

This module proposes bounded plans only. It never executes tasks, grants
permissions, or treats capability availability as user authorization.
"""
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.intelligence.planning.contracts import (
    GoalContract,
    IntentContract,
    IntentKind,
    PlanTaskKind,
    PlannedTask,
    TaskPlanContract,
)
from backend.app.intelligence.schemas import (
    ClassificationStatus,
    ContextTurn,
    TaskClassification,
    TaskType,
)


class PlanAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_valid: bool
    missing_capabilities: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    requires_authorization: bool
    requires_clarification: bool = False
    execution_permitted: bool = False

    @model_validator(mode="after")
    def enforce_planning_boundary(self) -> "PlanAssessment":
        if self.execution_permitted:
            raise ValueError("Planning cannot authorize or permit execution")
        return self


class PlanningResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    intent: IntentContract
    plan: TaskPlanContract
    assessment: PlanAssessment


class PlanningEngine:
    """Builds reproducible plans from deterministic task classifications."""

    _KIND_PATTERNS = {
        IntentKind.CREATE: ("create ", "write ", "draft ", "build "),
        IntentKind.ANALYZE: ("analyze ", "analyse ", "compare ", "review ", "assess "),
        IntentKind.TRANSFORM: ("translate ", "rewrite ", "summarize ", "summarise "),
        IntentKind.RETRIEVE: ("find ", "search ", "look up ", "lookup "),
    }
    _FOLLOW_UP_PREFIXES = (
        "make it ",
        "make this ",
        "shorten it",
        "expand it",
        "rewrite it",
        "rephrase it",
        "continue",
        "do the same",
        "compare them",
        "compare those",
        "what about it",
        "what about them",
        "what about that",
        "how about it",
        "how about them",
    )
    _FOLLOW_UP_KINDS = {
        IntentKind.TRANSFORM: (
            "make it ", "make this ", "shorten it", "expand it",
            "rewrite it", "rephrase it", "continue",
        ),
        IntentKind.ANALYZE: (
            "compare them", "compare those", "what about it",
            "what about them", "what about that", "how about it",
            "how about them",
        ),
    }
    _CAPABILITIES = {
        TaskType.CONVERSATION: "text_generation",
        TaskType.LANGUAGE_LOOKUP: "language_lookup",
        TaskType.PROVIDER_STATUS: "provider_status",
    }

    def plan(
        self,
        text: str,
        classification: TaskClassification,
        *,
        available_capabilities: Iterable[str] = (),
        conversation_history: Iterable[ContextTurn] = (),
    ) -> PlanningResult:
        normalized = text.strip().lower()
        history = tuple(
            ContextTurn.model_validate(turn.model_dump())
            for turn in conversation_history
            if isinstance(turn, ContextTurn)
        )[-20:]
        is_follow_up = normalized.startswith(self._FOLLOW_UP_PREFIXES)
        context_used = is_follow_up and bool(history)
        requires_clarification = is_follow_up and not history
        kind = self._infer_kind(
            normalized,
            classification,
            has_context=bool(history),
        )
        intent = IntentContract(
            kind=kind,
            summary=self._summarize(text),
            confidence=(
                classification.confidence
                if classification.status != ClassificationStatus.DEFAULT
                else min(classification.confidence, 0.8)
            ),
            ambiguities=(
                ("The request refers to prior context that was not provided",)
                if requires_clarification
                else (
                    ("The request may need clarification before action",)
                    if kind in {IntentKind.UNKNOWN, IntentKind.CONTROL}
                    else ()
                )
            ),
            context_used=context_used,
        )
        capability_id = self._CAPABILITIES.get(classification.task_type)
        goal = GoalContract(
            description=f"Address the user's request: {self._summarize(text)}",
            success_criteria=(
                "The result directly addresses the stated request",
                "The result is checked for completeness and consistency",
            ),
            constraints=(
                "Do not perform external or consequential actions during planning",
                "Do not treat a capability reference as authorization",
            ),
        )
        tasks = self._decompose(
            kind,
            capability_id,
            requires_clarification=requires_clarification,
        )
        plan = TaskPlanContract(
            goal=goal,
            tasks=tasks,
            rationale=(
                "Deterministic bounded decomposition; no model-generated "
                "steps or external actions are performed."
            ),
        )
        assessment = self.assess(
            plan,
            available_capabilities=available_capabilities,
            requires_authorization=(
                kind == IntentKind.CONTROL
                or classification.task_type == TaskType.UNSUPPORTED
            ),
            requires_clarification=requires_clarification,
        )
        return PlanningResult(
            intent=intent,
            plan=plan,
            assessment=assessment,
        )

    @staticmethod
    def _summarize(text: str) -> str:
        normalized = " ".join(text.split())
        return normalized[:500] or "Unspecified request"

    @classmethod
    def _infer_kind(
        cls,
        normalized: str,
        classification: TaskClassification,
        *,
        has_context: bool = False,
    ) -> IntentKind:
        if classification.task_type == TaskType.UNSUPPORTED:
            return IntentKind.CONTROL
        if has_context:
            for kind, prefixes in cls._FOLLOW_UP_KINDS.items():
                if normalized.startswith(prefixes):
                    return kind
        for kind, prefixes in cls._KIND_PATTERNS.items():
            if normalized.startswith(prefixes):
                return kind
        if classification.task_type in {
            TaskType.LANGUAGE_LOOKUP,
            TaskType.PROVIDER_STATUS,
        }:
            return IntentKind.RETRIEVE
        if classification.task_type == TaskType.CONVERSATION:
            return IntentKind.INFORM
        return IntentKind.UNKNOWN

    @staticmethod
    def _decompose(
        kind: IntentKind,
        capability_id: str | None,
        *,
        requires_clarification: bool = False,
    ) -> tuple[PlannedTask, ...]:
        if requires_clarification:
            return (
                PlannedTask(
                    task_id="clarify-context",
                    kind=PlanTaskKind.REQUEST_INPUT,
                    description=(
                        "Ask the user to identify the earlier content or subject "
                        "before interpreting this follow-up"
                    ),
                ),
                PlannedTask(
                    task_id="validate-context",
                    kind=PlanTaskKind.VALIDATE,
                    description="Validate the clarified reference before proceeding",
                    depends_on=("clarify-context",),
                ),
            )
        if kind == IntentKind.CONTROL:
            return (
                PlannedTask(
                    task_id="clarify-and-authorize",
                    kind=PlanTaskKind.REQUEST_INPUT,
                    description=(
                        "Clarify the requested action and obtain authorization "
                        "through the applicable protected workflow"
                    ),
                ),
                PlannedTask(
                    task_id="verify-policy",
                    kind=PlanTaskKind.VALIDATE,
                    description="Verify policy and authorization before any execution",
                    depends_on=("clarify-and-authorize",),
                ),
            )
        return (
            PlannedTask(
                task_id="produce-result",
                kind=(
                    PlanTaskKind.RETRIEVE
                    if kind == IntentKind.RETRIEVE
                    else PlanTaskKind.GENERATE
                ),
                description="Produce information or a result addressing the request",
                capability_id=capability_id,
            ),
            PlannedTask(
                task_id="validate-result",
                kind=PlanTaskKind.VALIDATE,
                description="Check the result against the goal and constraints",
                depends_on=("produce-result",),
            ),
        )

    @staticmethod
    def assess(
        plan: TaskPlanContract,
        *,
        available_capabilities: Iterable[str] = (),
        requires_authorization: bool = False,
    ) -> PlanAssessment:
        # Re-validate even instances constructed by trusted in-process callers.
        TaskPlanContract.model_validate(plan.model_dump())
        available = {
            value.strip().lower()
            for value in available_capabilities
            if isinstance(value, str) and value.strip()
        }
        referenced = {
            task.capability_id
            for task in plan.tasks
            if task.capability_id is not None
        }
        missing = tuple(sorted(referenced - available))
        return PlanAssessment(
            plan_valid=True,
            missing_capabilities=missing,
            requires_authorization=requires_authorization,
            requires_clarification=plan.tasks[0].kind == PlanTaskKind.REQUEST_INPUT
            and plan.tasks[0].task_id == "clarify-context",
            # Planning is deliberately never an authorization decision.
            execution_permitted=False,
        )
