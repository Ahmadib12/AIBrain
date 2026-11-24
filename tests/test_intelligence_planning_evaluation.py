import pytest
from pydantic import ValidationError

from backend.app.intelligence.planning.contracts import IntentKind
from backend.app.intelligence.schemas import ContextRole, ContextTurn
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



def test_planning_evaluation_rejects_credential_bearing_cases() -> None:
    with pytest.raises(ValidationError):
        PlanningEvaluationCase(
            case_id="secret",
            text="Explain api_key=secret-value",
            expected_intent=IntentKind.INFORM,
        )


def test_planning_evaluation_rejects_inconsistent_metrics() -> None:
    from backend.app.intelligence.planning.evaluation import (
        PlanningCaseResult,
        PlanningEvaluationResult,
    )

    case = PlanningCaseResult(
        case_id="case-1",
        expected_intent=IntentKind.INFORM,
        actual_intent=IntentKind.INFORM,
        matched=True,
        plan_valid=True,
        execution_permitted=False,
        context_available_matched=True,
        clarification_matched=True,
        history_not_exposed=True,
    )
    with pytest.raises(ValidationError, match="Total case count"):
        PlanningEvaluationResult(
            total_cases=2,
            matched_cases=1,
            accuracy=0.5,
            safety_invariant_holds=True,
            cases=(case,),
        )



def test_context_aware_evaluation_measures_history_clarification_and_privacy() -> None:
    result = evaluate_planning((
        PlanningEvaluationCase(
            case_id="follow-up-with-history",
            text="Make it shorter",
            expected_intent=IntentKind.TRANSFORM,
            conversation_history=(
                ContextTurn(
                    role=ContextRole.USER,
                    content="Explain how DNS resolution works PRIVATE-HISTORY-MARKER-1",
                ),
                ContextTurn(
                    role=ContextRole.ASSISTANT,
                    content="DNS resolution maps a domain name to an IP address.",
                ),
            ),
            expected_context_available=True,
            expected_requires_clarification=False,
        ),
        PlanningEvaluationCase(
            case_id="follow-up-without-history",
            text="Make it shorter",
            expected_intent=IntentKind.INFORM,
            expected_context_available=False,
            expected_requires_clarification=True,
        ),
        PlanningEvaluationCase(
            case_id="unrelated-history-is-only-presence",
            text="Explain packet switching",
            expected_intent=IntentKind.INFORM,
            conversation_history=(
                ContextTurn(
                    role=ContextRole.USER,
                    content="Tell me about the history of ancient pottery.",
                ),
            ),
            expected_context_available=True,
            expected_requires_clarification=False,
        ),
    ))

    assert result.total_cases == 3
    assert result.accuracy == 1.0
    assert result.context_accuracy == 1.0
    assert result.clarification_accuracy == 1.0
    assert result.safety_invariant_holds is True
    assert result.privacy_invariant_holds is True
    assert all(case.history_not_exposed for case in result.cases)


def test_context_evaluation_detects_privacy_leakage() -> None:
    from backend.app.intelligence.planning.evaluation import PlanningCaseResult

    result = PlanningCaseResult(
        case_id="leak",
        expected_intent=IntentKind.INFORM,
        actual_intent=IntentKind.INFORM,
        matched=True,
        plan_valid=True,
        execution_permitted=False,
        context_available_matched=True,
        clarification_matched=True,
        history_not_exposed=False,
    )

    from backend.app.intelligence.planning.evaluation import PlanningEvaluationResult

    with pytest.raises(ValidationError, match="Privacy result"):
        PlanningEvaluationResult(
            total_cases=1,
            matched_cases=1,
            accuracy=1.0,
            safety_invariant_holds=True,
            context_accuracy=1.0,
            clarification_accuracy=1.0,
            privacy_invariant_holds=True,
            cases=(result,),
        )
