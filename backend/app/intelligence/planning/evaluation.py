"""Small deterministic evaluation harness for intent and plan quality."""
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.planning.contracts import IntentKind
from backend.app.intelligence.planning.engine import PlanningEngine


class PlanningEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=2_000)
    expected_intent: IntentKind


class PlanningCaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    expected_intent: IntentKind
    actual_intent: IntentKind
    matched: bool
    plan_valid: bool
    execution_permitted: bool


class PlanningEvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    total_cases: int = Field(ge=0)
    matched_cases: int = Field(ge=0)
    accuracy: float = Field(ge=0.0, le=1.0)
    safety_invariant_holds: bool
    cases: tuple[PlanningCaseResult, ...] = Field(max_length=1_000)


def evaluate_planning(
    cases: Iterable[PlanningEvaluationCase],
    *,
    classifier: DeterministicTaskClassifier | None = None,
    planner: PlanningEngine | None = None,
) -> PlanningEvaluationResult:
    """Evaluate deterministic intent labels and non-execution invariants."""
    selected_classifier = classifier or DeterministicTaskClassifier()
    selected_planner = planner or PlanningEngine()
    case_list = tuple(cases)
    if len(case_list) > 1_000:
        raise ValueError("Planning evaluation is limited to 1000 cases")
    identifiers = [case.case_id for case in case_list]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Planning evaluation case IDs must be unique")

    results: list[PlanningCaseResult] = []
    for case in case_list:
        classification = selected_classifier.classify(case.text)
        planned = selected_planner.plan(case.text, classification)
        results.append(PlanningCaseResult(
            case_id=case.case_id,
            expected_intent=case.expected_intent,
            actual_intent=planned.intent.kind,
            matched=planned.intent.kind == case.expected_intent,
            plan_valid=planned.assessment.plan_valid,
            execution_permitted=planned.assessment.execution_permitted,
        ))

    matched = sum(item.matched for item in results)
    total = len(results)
    return PlanningEvaluationResult(
        total_cases=total,
        matched_cases=matched,
        accuracy=(matched / total if total else 1.0),
        safety_invariant_holds=all(
            item.plan_valid and not item.execution_permitted
            for item in results
        ),
        cases=tuple(results),
    )
