import pytest

from backend.app.intelligence.planning.agent_bridge import PlanRunProposalBridge
from backend.app.intelligence.planning.contracts import (
    GoalContract,
    IntentContract,
    IntentKind,
    PlanTaskKind,
    PlannedTask,
    TaskPlanContract,
)
from backend.app.intelligence.planning.engine import PlanAssessment, PlanningResult


class FakeRepository:
    def __init__(self):
        self.created = None

    def create_run(self, user_id, task_id, actions, registry):
        self.created = (user_id, task_id, actions, registry)
        return {"id": "proposal-1", "status": "proposed", "actions": actions}


class FakeRegistry:
    pass


def planning(*, requires_authorization=False, requires_clarification=False, missing=()):
    return PlanningResult(
        intent=IntentContract(
            kind=IntentKind.INFORM,
            summary="Explain networking",
            confidence=0.9,
        ),
        plan=TaskPlanContract(
            goal=GoalContract(
                description="Explain networking",
                success_criteria=("Provide an accurate explanation",),
            ),
            rationale="Bounded deterministic proposal.",
            tasks=(
                PlannedTask(
                    task_id="produce",
                    kind=PlanTaskKind.GENERATE,
                    description="Generate the explanation",
                    capability_id="text_generation",
                ),
                PlannedTask(
                    task_id="validate",
                    kind=PlanTaskKind.VALIDATE,
                    description="Validate the explanation",
                    depends_on=("produce",),
                ),
            ),
        ),
        assessment=PlanAssessment(
            plan_valid=True,
            requires_authorization=requires_authorization,
            requires_clarification=requires_clarification,
            missing_capabilities=tuple(missing),
            execution_permitted=False,
        ),
    )


def action(**changes):
    value = {
        "plan_task_id": "produce",
        "tool_id": "echo",
        "arguments": {"message": "hello"},
        "required_capability": "text_generation",
    }
    value.update(changes)
    return value


def test_plan_bridge_creates_only_durable_proposal():
    repository = FakeRepository()
    registry = FakeRegistry()
    result = PlanRunProposalBridge().create_proposal(
        "owner-1",
        "task-1",
        planning(),
        [action()],
        repository=repository,
        registry=registry,
    )
    assert result["status"] == "proposed"
    assert repository.created == (
        "owner-1",
        "task-1",
        [{
            "tool_id": "echo",
            "arguments": {"message": "hello"},
            "required_capability": "text_generation",
        }],
        registry,
    )


@pytest.mark.parametrize(
    "plan",
    [
        planning(requires_authorization=True),
        planning(requires_clarification=True),
        planning(missing=("text_generation",)),
    ],
)
def test_plan_bridge_rejects_unresolved_or_unauthorized_plans(plan):
    with pytest.raises(PermissionError, match="not eligible"):
        PlanRunProposalBridge().create_proposal(
            "owner-1", "task-1", plan, [action()],
            repository=FakeRepository(), registry=FakeRegistry(),
        )


def test_plan_bridge_rejects_capability_mismatch():
    with pytest.raises(PermissionError, match="does not match"):
        PlanRunProposalBridge().create_proposal(
            "owner-1", "task-1", planning(),
            [action(required_capability="send_email")],
            repository=FakeRepository(), registry=FakeRegistry(),
        )


def test_plan_bridge_rejects_unmapped_or_duplicate_plan_tasks():
    bridge = PlanRunProposalBridge()
    with pytest.raises(PermissionError, match="mapped exactly once"):
        bridge.create_proposal(
            "owner-1", "task-1", planning(), [],
            repository=FakeRepository(), registry=FakeRegistry(),
        )
    with pytest.raises(ValueError, match="only once"):
        bridge.create_proposal(
            "owner-1", "task-1", planning(), [action(), action()],
            repository=FakeRepository(), registry=FakeRegistry(),
        )


def test_plan_bridge_rejects_action_for_non_capability_task():
    with pytest.raises(PermissionError, match="declared plan capability"):
        PlanRunProposalBridge().create_proposal(
            "owner-1", "task-1", planning(),
            [action(plan_task_id="validate")],
            repository=FakeRepository(), registry=FakeRegistry(),
        )


def test_plan_bridge_rejects_model_supplied_extra_action_fields():
    with pytest.raises(ValueError, match="unsupported fields"):
        PlanRunProposalBridge().create_proposal(
            "owner-1", "task-1", planning(),
            [action(permission_granted=True)],
            repository=FakeRepository(), registry=FakeRegistry(),
        )
