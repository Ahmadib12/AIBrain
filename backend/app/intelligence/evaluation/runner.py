import asyncio
from dataclasses import dataclass
import time

from backend.app.intelligence.adapters import AdapterResult, CapabilityAdapter
from backend.app.intelligence.capabilities import (
    CapabilityMetadata,
    CapabilityRegistry,
)
from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.core import OrchestrationCore
from backend.app.intelligence.evaluation.cases import (
    EvaluationCase,
    EvaluationDataset,
    ExpectedClassification,
    ExpectedResponse,
)
from backend.app.intelligence.schemas import IntelligenceRequest


@dataclass(frozen=True)
class ClassificationDecision:
    task_type: str
    status: str
    confidence: float


@dataclass(frozen=True)
class ResponseDecision:
    task_type: str
    status: str
    selected_capabilities: tuple[str, ...]
    error_code: str | None


@dataclass(frozen=True)
class CaseRun:
    case: EvaluationCase
    classification_runs: tuple[ClassificationDecision, ...]
    response_runs: tuple[ResponseDecision, ...]
    classifier_timings_ns: tuple[int, ...]
    orchestration_timings_ns: tuple[int, ...]
    adapter_invocations: int

    @property
    def actual_classification(self) -> ClassificationDecision:
        return self.classification_runs[0]

    @property
    def actual_response(self) -> ResponseDecision:
        return self.response_runs[0]

    @property
    def expected_classification(self) -> ExpectedClassification:
        return self.case.expected.classification

    @property
    def expected_response(self) -> ExpectedResponse:
        return self.case.expected.response


@dataclass(frozen=True)
class EvaluationResult:
    dataset_id: str
    schema_version: int
    repetitions: int
    warmup_runs: int
    elapsed_ns: int
    cases: tuple[CaseRun, ...]


class EvaluationExecutionError(RuntimeError):
    CATEGORIES = frozenset({"request_construction", "execution"})

    def __init__(self, category: str) -> None:
        if category not in self.CATEGORIES:
            raise ValueError("Unsupported evaluation error category")
        self.category = category
        super().__init__(category)


class _FixedAdapter(CapabilityAdapter):
    def __init__(self) -> None:
        self.invocations = 0

    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        self.invocations += 1
        return AdapterResult(
            content="fixed evaluation response",
            metadata={"deterministic": True},
        )


def _decision_from_classification(value) -> ClassificationDecision:
    return ClassificationDecision(
        task_type=value.task_type.value,
        status=value.status.value,
        confidence=value.confidence,
    )


def _decision_from_response(value) -> ResponseDecision:
    return ResponseDecision(
        task_type=value.task_type.value,
        status=value.status.value,
        selected_capabilities=tuple(value.selected_capabilities),
        error_code=value.error_code,
    )


def _build_case_runtime(
    case: EvaluationCase,
    classifier: DeterministicTaskClassifier,
) -> tuple[OrchestrationCore, IntelligenceRequest, tuple[_FixedAdapter, ...]]:
    try:
        registry = CapabilityRegistry()
        adapters: dict[str, CapabilityAdapter] = {}
        fixed_adapters: list[_FixedAdapter] = []
        for setup in case.capabilities:
            registry.register(CapabilityMetadata(
                capability_id=setup.capability_id,
                name=setup.capability_id.replace("_", " ").title(),
                registered=True,
                implemented=setup.implemented,
                available=setup.available,
            ))
            if setup.adapter:
                adapter = _FixedAdapter()
                adapters[setup.capability_id] = adapter
                fixed_adapters.append(adapter)
        core = OrchestrationCore(
            classifier=classifier,
            capability_registry=registry,
            adapters=adapters,
        )
        request = IntelligenceRequest(
            messages=[{"role": "user", "content": case.input.text}],
            task_type=case.input.explicit_task_type,
        )
        return core, request, tuple(fixed_adapters)
    except Exception:
        raise EvaluationExecutionError("request_construction") from None


async def _run_once(
    case: EvaluationCase,
    classifier: DeterministicTaskClassifier,
    core: OrchestrationCore,
    request: IntelligenceRequest,
) -> tuple[ClassificationDecision, ResponseDecision, int, int]:
    try:
        started = time.perf_counter_ns()
        classification = classifier.classify(
            case.input.text,
            case.input.explicit_task_type,
        )
        classifier_elapsed = time.perf_counter_ns() - started

        started = time.perf_counter_ns()
        response = await core.process(request)
        orchestration_elapsed = time.perf_counter_ns() - started
    except Exception:
        raise EvaluationExecutionError("execution") from None
    return (
        _decision_from_classification(classification),
        _decision_from_response(response),
        classifier_elapsed,
        orchestration_elapsed,
    )


async def run_evaluation(
    dataset: EvaluationDataset,
    *,
    repetitions: int = 10,
    warmup_runs: int = 2,
) -> EvaluationResult:
    if type(repetitions) is not int or not 1 <= repetitions <= 10_000:
        raise ValueError("repetitions must be an integer from 1 to 10000")
    if type(warmup_runs) is not int or not 0 <= warmup_runs <= 10_000:
        raise ValueError("warmup_runs must be an integer from 0 to 10000")

    classifier = DeterministicTaskClassifier()
    runtimes = [
        (case, *_build_case_runtime(case, classifier))
        for case in dataset.cases
    ]

    for _ in range(warmup_runs):
        for case, core, request, _ in runtimes:
            await _run_once(case, classifier, core, request)

    measured = [
        {
            "classifications": [],
            "responses": [],
            "classifier_timings": [],
            "orchestration_timings": [],
            "adapters": adapters,
        }
        for _, _, _, adapters in runtimes
    ]
    started = time.perf_counter_ns()
    for _ in range(repetitions):
        for index, (case, core, request, _) in enumerate(runtimes):
            (
                classification,
                response,
                classifier_elapsed,
                orchestration_elapsed,
            ) = await _run_once(case, classifier, core, request)
            measured[index]["classifications"].append(classification)
            measured[index]["responses"].append(response)
            measured[index]["classifier_timings"].append(classifier_elapsed)
            measured[index]["orchestration_timings"].append(orchestration_elapsed)
    elapsed_ns = time.perf_counter_ns() - started

    case_runs = tuple(
        CaseRun(
            case=case,
            classification_runs=tuple(values["classifications"]),
            response_runs=tuple(values["responses"]),
            classifier_timings_ns=tuple(values["classifier_timings"]),
            orchestration_timings_ns=tuple(
                values["orchestration_timings"]
            ),
            adapter_invocations=sum(
                adapter.invocations for adapter in values["adapters"]
            ),
        )
        for (case, _, _, _), values in zip(runtimes, measured, strict=True)
    )
    return EvaluationResult(
        dataset_id=dataset.dataset_id,
        schema_version=dataset.schema_version,
        repetitions=repetitions,
        warmup_runs=warmup_runs,
        elapsed_ns=elapsed_ns,
        cases=case_runs,
    )


def run_evaluation_sync(
    dataset: EvaluationDataset,
    *,
    repetitions: int = 10,
    warmup_runs: int = 2,
) -> EvaluationResult:
    return asyncio.run(run_evaluation(
        dataset,
        repetitions=repetitions,
        warmup_runs=warmup_runs,
    ))
