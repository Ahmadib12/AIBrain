"""Small deterministic evaluation harness for intent and plan quality."""
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.planning.contracts import IntentKind
from backend.app.intelligence.planning.engine import PlanningEngine
from backend.app.intelligence.schemas import ContextTurn, contains_credential_content


class PlanningEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=2_000)
    expected_intent: IntentKind
    conversation_history: tuple[ContextTurn, ...] = Field(default_factory=tuple, max_length=20)
    expected_context_available: bool = False
    expected_requires_clarification: bool = False

    @field_validator("text")
    @classmethod
    def validate_public_text(cls, value: str) -> str:
        if not value.strip() or contains_credential_content(value):
            raise ValueError("Evaluation text must be nonblank and credential-free")
        return value


class PlanningCaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    expected_intent: IntentKind
    actual_intent: IntentKind
    matched: bool
    plan_valid: bool
    execution_permitted: bool
    context_available_matched: bool
    clarification_matched: bool
    history_not_exposed: bool


class PlanningEvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    total_cases: int = Field(ge=0)
    matched_cases: int = Field(ge=0)
    accuracy: float = Field(ge=0.0, le=1.0)
    safety_invariant_holds: bool
    context_accuracy: float = Field(ge=0.0, le=1.0)
    clarification_accuracy: float = Field(ge=0.0, le=1.0)
    privacy_invariant_holds: bool
    cases: tuple[PlanningCaseResult, ...] = Field(max_length=1_000)

    @model_validator(mode="after")
    def validate_aggregate_metrics(self) -> "PlanningEvaluationResult":
        if self.total_cases != len(self.cases):
            raise ValueError("Total case count must match the result entries")
        actual_matches = sum(case.matched for case in self.cases)
        if self.matched_cases != actual_matches:
            raise ValueError("Matched case count must match the result entries")
        expected_accuracy = (
            actual_matches / self.total_cases if self.total_cases else 1.0
        )
        if self.accuracy != expected_accuracy:
            raise ValueError("Accuracy must match the measured case results")
        expected_safety = all(
            case.plan_valid and not case.execution_permitted
            for case in self.cases
        )
        if self.safety_invariant_holds != expected_safety:
            raise ValueError("Safety result must match the measured case results")
        expected_context_accuracy = (
            sum(case.context_available_matched for case in self.cases) / self.total_cases
            if self.total_cases else 1.0
        )
        if self.context_accuracy != expected_context_accuracy:
            raise ValueError("Context accuracy must match the measured case results")
        expected_clarification_accuracy = (
            sum(case.clarification_matched for case in self.cases) / self.total_cases
            if self.total_cases else 1.0
        )
        if self.clarification_accuracy != expected_clarification_accuracy:
            raise ValueError("Clarification accuracy must match the measured case results")
        expected_privacy = all(case.history_not_exposed for case in self.cases)
        if self.privacy_invariant_holds != expected_privacy:
            raise ValueError("Privacy result must match the measured case results")
        return self


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
        planned = selected_planner.plan(
            case.text,
            classification,
            conversation_history=case.conversation_history,
        )
        serialized_plan = planned.model_dump(mode="json")
        serialized_text = str(serialized_plan)
        history_not_exposed = all(
            turn.content not in serialized_text
            for turn in case.conversation_history
        )
        results.append(PlanningCaseResult(
            case_id=case.case_id,
            expected_intent=case.expected_intent,
            actual_intent=planned.intent.kind,
            matched=planned.intent.kind == case.expected_intent,
            plan_valid=planned.assessment.plan_valid,
            execution_permitted=planned.assessment.execution_permitted,
            context_available_matched=(
                planned.intent.context_available == case.expected_context_available
            ),
            clarification_matched=(
                planned.assessment.requires_clarification
                == case.expected_requires_clarification
            ),
            history_not_exposed=history_not_exposed,
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
        context_accuracy=(
            sum(item.context_available_matched for item in results) / total
            if total else 1.0
        ),
        clarification_accuracy=(
            sum(item.clarification_matched for item in results) / total
            if total else 1.0
        ),
        privacy_invariant_holds=all(item.history_not_exposed for item in results),
        cases=tuple(results),
    )
