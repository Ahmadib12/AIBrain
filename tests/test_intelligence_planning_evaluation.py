import pytest
from pydantic import ValidationError

from backend.app.intelligence.planning.contracts import IntentKind
from backend.app.intelligence.planning.evaluation import (
    PlanningEvaluationCase,
    evaluate_planning,
)


def test_planning_evaluation_reports_accuracy_and_safety() -> None:
    result = evaluate_planning((
        PlanningEvaluationCase(
            case_id="create",
            text="Create a revision schedule",
            expected_intent=IntentKind.CREATE,
        ),
        PlanningEvaluationCase(
            case_id="analyze",
            text="Compare two routers",
            expected_intent=IntentKind.ANALYZE,
        ),
        PlanningEvaluationCase(
            case_id="inform",
            text="Explain packet switching",
            expected_intent=IntentKind.INFORM,
        ),
    ))

    assert result.total_cases == 3
    assert result.matched_cases == 3
    assert result.accuracy == 1.0
    assert result.safety_invariant_holds is True
    assert all(not case.execution_permitted for case in result.cases)


def test_planning_evaluation_reports_mismatch() -> None:
    result = evaluate_planning((
        PlanningEvaluationCase(
            case_id="wrong-label",
            text="Compare two routers",
            expected_intent=IntentKind.CREATE,
        ),
    ))

    assert result.matched_cases == 0
    assert result.accuracy == 0.0
    assert result.cases[0].matched is False


def test_planning_evaluation_rejects_duplicate_case_ids() -> None:
    case = PlanningEvaluationCase(
        case_id="duplicate",
        text="Explain networking",
        expected_intent=IntentKind.INFORM,
    )
    with pytest.raises(ValueError, match="unique"):
        evaluate_planning((case, case))


def test_planning_evaluation_rejects_oversized_dataset() -> None:
    cases = tuple(
        PlanningEvaluationCase(
            case_id=f"case-{index}",
            text="Explain networking",
            expected_intent=IntentKind.INFORM,
        )
        for index in range(1_001)
    )
    with pytest.raises(ValueError, match="1000"):
        evaluate_planning(cases)


def test_planning_evaluation_case_is_strict() -> None:
    with pytest.raises(ValidationError):
        PlanningEvaluationCase(
            case_id="unsafe",
            text="Explain networking",
            expected_intent=IntentKind.INFORM,
            execute=True,
        )
