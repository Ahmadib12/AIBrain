import pytest
from pydantic import ValidationError

from backend.app.intelligence.planning.contracts import (
    GoalContract,
    PlanTaskKind,
    PlannedTask,
    TaskPlanContract,
)
from backend.app.intelligence.planning.lifecycle import (
    PlanningLifecycle,
    RecoveryAction,
    RecoveryFailureKind,
)


@pytest.fixture
def lifecycle() -> PlanningLifecycle:
    return PlanningLifecycle()


@pytest.fixture
def plan() -> TaskPlanContract:
    return TaskPlanContract(
        goal=GoalContract(
            description="Prepare a network security review",
            success_criteria=("Identify key risks", "Provide mitigations"),
            constraints=("Do not change production systems",),
        ),
        tasks=(
            PlannedTask(
                task_id="collect",
                kind=PlanTaskKind.RETRIEVE,
                description="Collect the supplied network design",
                capability_id="text_generation",
            ),
            PlannedTask(
                task_id="analyze",
                kind=PlanTaskKind.REASON,
                description="Analyze the design",
                depends_on=("collect",),
            ),
            PlannedTask(
                task_id="validate",
                kind=PlanTaskKind.VALIDATE,
                description="Check findings against the goal",
                depends_on=("analyze",),
            ),
        ),
        rationale="A bounded three-step proposal.",
    )


def test_goal_refinement_uses_only_explicit_changes(lifecycle, plan):
    result = lifecycle.refine_goal(
        plan.goal,
        success_criteria=("Identify key risks", "Rank mitigations"),
    )

    assert result.changed is True
    assert result.original_goal_id == plan.goal.goal_id
    assert result.proposed_goal.success_criteria[-1] == "Rank mitigations"
    assert result.proposed_goal.description == plan.goal.description
    assert result.requires_user_confirmation is True


def test_unchanged_goal_is_still_not_implicitly_accepted(lifecycle, plan):
    result = lifecycle.refine_goal(plan.goal)

    assert result.changed is False
    assert result.requires_user_confirmation is True


def test_goal_refinement_rejects_credentials(lifecycle, plan):
    with pytest.raises(ValidationError):
        lifecycle.refine_goal(plan.goal, description="Use api_key=private")


def test_multistep_composition_appends_ordered_tasks(lifecycle, plan):
    extended = lifecycle.extend_plan(
        plan,
        (
            PlannedTask(
                task_id="draft",
                kind=PlanTaskKind.GENERATE,
                description="Draft the report",
                depends_on=("analyze",),
            ),
            PlannedTask(
                task_id="final-check",
                kind=PlanTaskKind.VALIDATE,
                description="Validate the draft",
                depends_on=("draft",),
            ),
        ),
    )

    assert [task.task_id for task in extended.tasks] == [
        "collect", "analyze", "validate", "draft", "final-check"
    ]
    assert extended.tasks[-1].depends_on == ("draft",)


def test_multistep_composition_rejects_forward_or_unknown_dependency(lifecycle, plan):
    with pytest.raises(ValidationError, match="earlier task"):
        lifecycle.extend_plan(
            plan,
            (PlannedTask(
                task_id="new-step",
                kind=PlanTaskKind.REASON,
                description="A step with an unknown dependency",
                depends_on=("not-present",),
            ),),
        )


def test_multistep_composition_rejects_duplicate_task_ids(lifecycle, plan):
    with pytest.raises(ValidationError, match="unique"):
        lifecycle.extend_plan(
            plan,
            (PlannedTask(
                task_id="analyze",
                kind=PlanTaskKind.REASON,
                description="Duplicate identifier",
            ),),
        )


def test_multistep_composition_enforces_twenty_task_limit(lifecycle, plan):
    tasks = tuple(
        PlannedTask(
            task_id=f"extra-{index}",
            kind=PlanTaskKind.REASON,
            description=f"Additional step {index}",
        )
        for index in range(18)
    )
    with pytest.raises(ValueError, match="20 tasks"):
        lifecycle.extend_plan(plan, tasks)


def test_plan_validation_reports_missing_capability(lifecycle, plan):
    result = lifecycle.validate_plan(plan)

    assert result.structurally_valid is True
    assert result.capabilities_available is False
    assert result.safe_to_propose is False
    assert result.execution_permitted is False
    assert result.issues[0].code == "missing_capability"
    assert result.issues[0].task_id == "collect"


def test_plan_validation_accepts_available_capability_but_never_authorizes(lifecycle, plan):
    result = lifecycle.validate_plan(
        plan,
        available_capabilities=("text_generation",),
    )

    assert result.safe_to_propose is True
    assert result.issues == ()
    assert result.execution_permitted is False


def test_plan_validation_blocks_unresolved_ambiguity(lifecycle, plan):
    result = lifecycle.validate_plan(
        plan,
        available_capabilities=("text_generation",),
        requires_clarification=True,
    )

    assert result.safe_to_propose is False
    assert result.issues[0].code == "clarification_required"


def test_validation_contract_cannot_claim_execution_permission():
    with pytest.raises(ValidationError, match="cannot authorize"):
        from backend.app.intelligence.planning.lifecycle import PlanValidationResult

        PlanValidationResult(
            structurally_valid=True,
            capabilities_available=True,
            requires_clarification=False,
            safe_to_propose=True,
            execution_permitted=True,
        )


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (RecoveryFailureKind.TRANSIENT, RecoveryAction.RETRY_RECOMMENDED),
        (RecoveryFailureKind.INVALID_OUTPUT, RecoveryAction.REPLAN_RECOMMENDED),
        (RecoveryFailureKind.MISSING_CAPABILITY, RecoveryAction.STOP),
        (RecoveryFailureKind.AMBIGUOUS, RecoveryAction.REQUEST_INPUT),
        (RecoveryFailureKind.DEPENDENCY_FAILED, RecoveryAction.REPLAN_RECOMMENDED),
        (RecoveryFailureKind.UNKNOWN, RecoveryAction.STOP),
    ],
)
def test_recovery_is_recommendation_only(lifecycle, plan, failure, expected):
    result = lifecycle.recommend_recovery(
        plan,
        failed_task_id="analyze",
        failure_kind=failure,
    )

    assert result.action is expected
    assert result.execution_permitted is False
    assert result.requires_user_input is (failure is RecoveryFailureKind.AMBIGUOUS)


def test_recovery_rejects_task_outside_plan(lifecycle, plan):
    with pytest.raises(ValueError, match="belong"):
        lifecycle.recommend_recovery(
            plan,
            failed_task_id="not-in-plan",
            failure_kind=RecoveryFailureKind.UNKNOWN,
        )


def test_recovery_contract_cannot_authorize_execution():
    from backend.app.intelligence.planning.lifecycle import RecoveryRecommendation

    with pytest.raises(ValidationError, match="cannot authorize"):
        RecoveryRecommendation(
            failed_task_id="task-1",
            failure_kind=RecoveryFailureKind.UNKNOWN,
            action=RecoveryAction.STOP,
            rationale="Stop.",
            requires_user_input=False,
            execution_permitted=True,
        )
