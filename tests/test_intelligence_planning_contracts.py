import pytest
from pydantic import ValidationError

from backend.app.intelligence.planning.contracts import (
    GoalContract,
    IntentContract,
    IntentKind,
    PlanTaskKind,
    PlannedTask,
    TaskPlanContract,
)


def make_goal() -> GoalContract:
    return GoalContract(
        description="Prepare a verified comparison",
        success_criteria=("Compare the supplied options",),
        constraints=("Do not purchase anything",),
    )


def test_intent_contract_is_typed_bounded_and_immutable() -> None:
    intent = IntentContract(
        kind=IntentKind.ANALYZE,
        summary="Compare two devices",
        confidence=0.9,
        ambiguities=("Storage capacity is not specified",),
    )

    assert intent.kind is IntentKind.ANALYZE
    assert 0 <= intent.confidence <= 1
    with pytest.raises(ValidationError):
        intent.summary = "Changed"


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_intent_rejects_out_of_range_confidence(confidence: float) -> None:
    with pytest.raises(ValidationError):
        IntentContract(
            kind=IntentKind.UNKNOWN,
            summary="Unclear request",
            confidence=confidence,
        )


@pytest.mark.parametrize(
    "summary",
    ["   ", "Use api_key=secret-value", "Bearer abcdefghijklmnop"],
)
def test_intent_rejects_blank_or_credential_content(summary: str) -> None:
    with pytest.raises(ValidationError):
        IntentContract(
            kind=IntentKind.INFORM,
            summary=summary,
            confidence=0.5,
        )


def test_goal_requires_at_least_one_success_criterion() -> None:
    with pytest.raises(ValidationError):
        GoalContract(
            description="Complete a task",
            success_criteria=(),
        )


def test_plan_accepts_ordered_dependency_graph() -> None:
    plan = TaskPlanContract(
        goal=make_goal(),
        rationale="Gather facts, compare them, then validate the result.",
        tasks=(
            PlannedTask(
                task_id="gather",
                kind=PlanTaskKind.RETRIEVE,
                description="Gather the relevant specifications",
                capability_id="web_research",
            ),
            PlannedTask(
                task_id="compare",
                kind=PlanTaskKind.REASON,
                description="Compare the specifications",
                depends_on=("gather",),
            ),
            PlannedTask(
                task_id="check",
                kind=PlanTaskKind.VALIDATE,
                description="Check that the comparison meets the goal",
                depends_on=("compare",),
            ),
        ),
    )

    assert len(plan.tasks) == 3
    assert plan.tasks[2].depends_on == ("compare",)


def test_plan_rejects_dependency_on_unknown_or_later_task() -> None:
    with pytest.raises(ValidationError):
        TaskPlanContract(
            goal=make_goal(),
            rationale="Invalid forward reference.",
            tasks=(
                PlannedTask(
                    task_id="first",
                    kind=PlanTaskKind.REASON,
                    description="First step",
                    depends_on=("second",),
                ),
                PlannedTask(
                    task_id="second",
                    kind=PlanTaskKind.VALIDATE,
                    description="Second step",
                ),
            ),
        )


def test_plan_rejects_duplicate_task_ids() -> None:
    task = PlannedTask(
        task_id="same",
        kind=PlanTaskKind.REASON,
        description="A step",
    )
    with pytest.raises(ValidationError):
        TaskPlanContract(
            goal=make_goal(),
            rationale="Duplicate task identifiers.",
            tasks=(task, task),
        )


def test_plan_rejects_duplicate_dependencies() -> None:
    with pytest.raises(ValidationError):
        PlannedTask(
            task_id="later",
            kind=PlanTaskKind.REASON,
            description="A step",
            depends_on=("first", "first"),
        )


def test_plan_rejects_credentials_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        PlannedTask(
            task_id="unsafe",
            kind=PlanTaskKind.REASON,
            description="Use token=secret-value",
        )

    with pytest.raises(ValidationError):
        IntentContract(
            kind=IntentKind.CONTROL,
            summary="Do something",
            confidence=0.5,
            permission_granted=True,
        )


def test_plan_is_bounded_to_twenty_tasks() -> None:
    tasks = tuple(
        PlannedTask(
            task_id=f"task-{index}",
            kind=PlanTaskKind.REASON,
            description=f"Step {index}",
        )
        for index in range(21)
    )
    with pytest.raises(ValidationError):
        TaskPlanContract(
            goal=make_goal(),
            rationale="Too many steps.",
            tasks=tasks,
        )


def test_capability_reference_does_not_imply_permission() -> None:
    task = PlannedTask(
        task_id="send",
        kind=PlanTaskKind.GENERATE,
        description="Prepare an email draft",
        capability_id="email",
    )

    assert task.capability_id == "email"
    assert "permission" not in task.model_fields
