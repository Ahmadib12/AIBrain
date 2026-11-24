import pytest
from pydantic import ValidationError

from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.planning.contracts import IntentKind, PlanTaskKind
from backend.app.intelligence.planning.engine import PlanningEngine
from backend.app.intelligence.schemas import ContextRole, ContextTurn, TaskType


@pytest.fixture
def planner() -> PlanningEngine:
    return PlanningEngine()


@pytest.fixture
def classifier() -> DeterministicTaskClassifier:
    return DeterministicTaskClassifier()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Create a study timetable", IntentKind.CREATE),
        ("Compare these two phones", IntentKind.ANALYZE),
        ("Translate this paragraph", IntentKind.TRANSFORM),
        ("Find the official documentation", IntentKind.RETRIEVE),
        ("Explain how DNS works", IntentKind.INFORM),
    ],
)
def test_deterministic_intent_extraction(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
    text: str,
    expected: IntentKind,
) -> None:
    classification = classifier.classify(text)
    result = planner.plan(text, classification)

    assert result.intent.kind is expected
    assert result.intent.summary == text
    assert result.assessment.execution_permitted is False


def test_explicit_task_classification_is_preserved(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    text = "Lookup language"
    classification = classifier.classify(text, "language_lookup")
    result = planner.plan(
        text,
        classification,
        available_capabilities=("language_lookup",),
    )

    assert classification.task_type is TaskType.LANGUAGE_LOOKUP
    assert result.intent.kind is IntentKind.RETRIEVE
    assert result.assessment.missing_capabilities == ()
    assert result.plan.tasks[0].capability_id == "language_lookup"


def test_goal_contains_success_criteria_and_non_action_constraints(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    result = planner.plan(
        "Compare two laptops",
        classifier.classify("Compare two laptops"),
    )

    assert len(result.plan.goal.success_criteria) >= 1
    assert any("consequential actions" in item for item in result.plan.goal.constraints)


def test_decomposition_is_bounded_and_dependency_ordered(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    result = planner.plan(
        "Analyze this report",
        classifier.classify("Analyze this report"),
    )

    assert 1 <= len(result.plan.tasks) <= 20
    assert result.plan.tasks[1].depends_on == ("produce-result",)
    assert result.plan.tasks[1].kind is PlanTaskKind.VALIDATE


def test_missing_capability_is_reported_without_authorizing_execution(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    result = planner.plan(
        "Explain routing",
        classifier.classify("Explain routing"),
    )

    assert result.assessment.plan_valid is True
    assert result.assessment.missing_capabilities == ("text_generation",)
    assert result.assessment.execution_permitted is False


def test_available_capability_is_not_permission(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    result = planner.plan(
        "Explain routing",
        classifier.classify("Explain routing"),
        available_capabilities=("text_generation",),
    )

    assert result.assessment.missing_capabilities == ()
    assert result.assessment.execution_permitted is False


def test_unsupported_consequential_request_stops_at_authorization_boundary(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    text = "Send an email to my manager"
    result = planner.plan(text, classifier.classify(text))

    assert result.intent.kind is IntentKind.CONTROL
    assert result.assessment.requires_authorization is True
    assert result.assessment.execution_permitted is False
    assert result.plan.tasks[0].kind is PlanTaskKind.REQUEST_INPUT
    assert result.plan.tasks[1].kind is PlanTaskKind.VALIDATE
    assert all(task.capability_id is None for task in result.plan.tasks)


def test_planning_output_is_deterministic_except_generated_identifiers(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    text = "Compare two devices"
    classification = classifier.classify(text)
    first = planner.plan(text, classification)
    second = planner.plan(text, classification)

    assert first.intent.kind == second.intent.kind
    assert first.intent.summary == second.intent.summary
    assert first.plan.goal.description == second.plan.goal.description
    assert first.plan.tasks == second.plan.tasks
    assert first.assessment == second.assessment


def test_planner_rejects_credential_content(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    text = "Explain api_key=super-secret"
    with pytest.raises(ValidationError):
        planner.plan(text, classifier.classify(text))



def test_planning_assessment_cannot_grant_execution() -> None:
    from backend.app.intelligence.planning.engine import PlanAssessment

    with pytest.raises(ValidationError, match="cannot authorize"):
        PlanAssessment(
            plan_valid=True,
            requires_authorization=False,
            execution_permitted=True,
        )



def test_follow_up_uses_bounded_prior_context_without_copying_it_into_summary(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    text = "Make it shorter"
    history = (
        ContextTurn(role=ContextRole.USER, content="Explain how DNS works"),
        ContextTurn(role=ContextRole.ASSISTANT, content="DNS translates domain names into IP addresses."),
    )

    result = planner.plan(
        text,
        classifier.classify(text),
        conversation_history=history,
        available_capabilities=("text_generation",),
    )

    assert result.intent.kind is IntentKind.TRANSFORM
    assert result.intent.context_available is True
    assert result.intent.summary == text
    assert "Explain how DNS works" not in str(result.model_dump())
    assert "DNS translates domain names" not in str(result.model_dump())
    assert result.assessment.requires_clarification is False
    assert result.assessment.execution_permitted is False
    assert result.plan.tasks[0].kind is PlanTaskKind.GENERATE


def test_contextual_follow_up_without_history_requests_clarification(
    planner: PlanningEngine,
    classifier: DeterministicTaskClassifier,
) -> None:
    text = "Make it shorter"
    result = planner.plan(text, classifier.classify(text))

    assert result.intent.context_available is False
    assert result.assessment.requires_clarification is True
    assert result.assessment.requires_authorization is False
    assert result.assessment.execution_permitted is False
    assert result.intent.ambiguities
    assert result.plan.tasks[0].kind is PlanTaskKind.REQUEST_INPUT
    assert result.plan.tasks[0].task_id == "clarify-context"
