import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from backend.app.intelligence.evaluation.cases import (
    CaseInput,
    DatasetSchemaError,
    EvaluationCase,
    EvaluationDataset,
    ExpectedClassification,
    ExpectedOutcome,
    ExpectedResponse,
    load_dataset,
    parse_dataset,
)
from backend.app.intelligence.evaluation.metrics import calculate_metrics
from backend.app.intelligence.evaluation.report import (
    build_report,
    render_json_report,
)
from backend.app.intelligence.evaluation.runner import (
    CaseRun,
    ClassificationDecision,
    EvaluationResult,
    ResponseDecision,
    run_evaluation,
)
from backend.app.intelligence.evaluation import runner
from backend.app.intelligence.evaluation import __main__ as evaluation_cli


_ROOT = Path(__file__).resolve().parents[1]


def _case(
    case_id: str,
    expected_task: str,
    expected_status: str,
    expected_capabilities: tuple[str, ...],
    expected_response_status: str,
    expected_error: str | None,
    actual_task: str,
    actual_classification_status: str,
    actual_capabilities: tuple[str, ...],
    actual_response_status: str,
    actual_error: str | None,
    *,
    adapter_invocations: int = 0,
    classification_runs: tuple[ClassificationDecision, ...] | None = None,
    response_runs: tuple[ResponseDecision, ...] | None = None,
) -> CaseRun:
    case = EvaluationCase(
        case_id=case_id,
        category="metric-test",
        input=CaseInput("Synthetic metric input.", None),
        capabilities=(),
        expected=ExpectedOutcome(
            classification=ExpectedClassification(
                task_type=expected_task,
                status=expected_status,
            ),
            response=ExpectedResponse(
                task_type=expected_task,
                status=expected_response_status,
                selected_capabilities=expected_capabilities,
                error_code=expected_error,
            ),
        ),
    )
    classification = ClassificationDecision(
        task_type=actual_task,
        status=actual_classification_status,
        confidence=0.5,
    )
    response = ResponseDecision(
        task_type=actual_task,
        status=actual_response_status,
        selected_capabilities=actual_capabilities,
        error_code=actual_error,
    )
    return CaseRun(
        case=case,
        classification_runs=classification_runs or (classification,),
        response_runs=response_runs or (response,),
        classifier_timings_ns=(1,),
        orchestration_timings_ns=(2,),
        adapter_invocations=adapter_invocations,
    )


def test_default_dataset_loads_with_unique_synthetic_cases() -> None:
    dataset = load_dataset()

    assert dataset.schema_version == 1
    assert dataset.dataset_id == "milestone4a_v1"
    assert len(dataset.cases) == 8
    assert len({case.case_id for case in dataset.cases}) == 8


def test_historical_baseline_artifact_schema_and_identity() -> None:
    baseline_path = (
        _ROOT
        / "tests/data/intelligence_eval/milestone4a_baseline_preimplementation.json"
    )
    dataset_path = (
        _ROOT / "tests/data/intelligence_eval/milestone4a_v1.json"
    )
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))

    assert baseline_path != dataset_path
    assert set(baseline) == {
        "artifact_schema_version",
        "artifact_id",
        "artifact_kind",
        "artifact_status",
        "implementation_state",
        "evaluation_dataset_id",
        "case_count",
        "warmup_runs_per_case",
        "measured_runs_per_case",
        "measured_samples_per_metric",
        "reporting_provenance",
        "observed_cases",
        "reported_historical_metrics",
        "not_measured_metrics",
        "performance_statistics",
    }
    assert baseline["artifact_schema_version"] == 1
    assert baseline["artifact_id"] == "milestone4a_baseline_preimplementation"
    assert baseline["artifact_kind"] == "historical_preimplementation_baseline"
    assert baseline["artifact_status"] == "immutable_historical_record"
    assert baseline["implementation_state"] == (
        "captured before Phase 4A evaluator implementation"
    )
    assert baseline["evaluation_dataset_id"] == dataset["dataset_id"]
    assert baseline["case_count"] == 8
    assert baseline["warmup_runs_per_case"] == 10
    assert baseline["measured_runs_per_case"] == 100
    assert baseline["measured_samples_per_metric"] == 800
    assert [case["id"] for case in baseline["observed_cases"]] == [
        "explicit-language",
        "default-language",
        "conversation-default",
        "unsupported-action",
        "explanatory-question",
        "unavailable-capability",
        "missing-adapter",
        "unknown-explicit",
    ]
    observed = {
        case["id"]: (
            case["classification"]["task_type"],
            case["classification"]["status"],
            case["response"]["task_type"],
            case["response"]["status"],
            tuple(case["response"]["selected_capabilities"]),
            case["response"]["error_code"],
        )
        for case in baseline["observed_cases"]
    }
    assert observed == {
        "explicit-language": (
            "language_lookup",
            "explicit",
            "language_lookup",
            "completed",
            ("language_lookup",),
            None,
        ),
        "default-language": (
            "language_lookup",
            "default",
            "language_lookup",
            "completed",
            ("language_lookup",),
            None,
        ),
        "conversation-default": (
            "conversation",
            "default",
            "conversation",
            "completed",
            ("text_generation",),
            None,
        ),
        "unsupported-action": (
            "unsupported",
            "unsupported",
            "unsupported",
            "unsupported",
            (),
            "UNSUPPORTED_TASK",
        ),
        "explanatory-question": (
            "conversation",
            "default",
            "conversation",
            "completed",
            ("text_generation",),
            None,
        ),
        "unavailable-capability": (
            "provider_status",
            "default",
            "provider_status",
            "error",
            (),
            "CAPABILITY_UNAVAILABLE",
        ),
        "missing-adapter": (
            "provider_status",
            "default",
            "provider_status",
            "error",
            (),
            "ADAPTER_UNAVAILABLE",
        ),
        "unknown-explicit": (
            "unsupported",
            "unsupported",
            "unsupported",
            "unsupported",
            (),
            "UNSUPPORTED_TASK",
        ),
    }
    assert baseline["reported_historical_metrics"]["provenance"] == (
        "reported_historical_not_independently_calculated"
    )
    assert baseline["reported_historical_metrics"]["task_classification_accuracy"] == "8/8"
    assert baseline["reported_historical_metrics"]["capability_micro_f1"] == 1.0
    assert baseline["reported_historical_metrics"]["decision_consistency"] == (
        "not measured in pre-framework single-decision capture"
    )
    assert set(baseline["not_measured_metrics"]) >= {
        "decision_consistency",
        "per-task precision",
        "per-task recall",
        "per-task F1",
        "macro-F1",
    }
    assert baseline["performance_statistics"]["classifier"] == {
        "samples": 800,
        "median_ns": 4604,
        "p95_ns": 6142,
    }
    assert baseline["performance_statistics"][
        "core_with_fixed_offline_adapters"
    ] == {
        "samples": 800,
        "median_ns": 45793,
        "p95_ns": 53715,
    }


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"schema_version": 2, "dataset_id": "v2", "cases": []},
        {
            "schema_version": 1,
            "dataset_id": "v1",
            "cases": [{"id": "bad"}],
        },
    ],
)
def test_invalid_dataset_schema_is_rejected(value: dict) -> None:
    with pytest.raises(DatasetSchemaError):
        parse_dataset(value)


def test_explicit_task_type_must_match_expected_classification() -> None:
    value = json.loads(
        (_ROOT / "tests/data/intelligence_eval/milestone4a_v1.json")
        .read_text(encoding="utf-8")
    )
    case = value["cases"][0]
    case["expected"]["classification"] = {
        "task_type": "conversation",
        "status": "explicit",
    }
    case["expected"]["response"] = {
        "task_type": "conversation",
        "status": "completed",
        "selected_capabilities": ["text_generation"],
        "error_code": None,
    }
    case["capabilities"] = [{
        "id": "text_generation",
        "implemented": True,
        "available": True,
        "adapter": True,
    }]

    with pytest.raises(DatasetSchemaError):
        parse_dataset(value)


def test_explicit_task_alias_accepts_its_expected_classification() -> None:
    value = json.loads(
        (_ROOT / "tests/data/intelligence_eval/milestone4a_v1.json")
        .read_text(encoding="utf-8")
    )
    case = value["cases"][0]
    case["input"]["task_type"] = "general"
    case["expected"]["classification"] = {
        "task_type": "conversation",
        "status": "explicit",
    }
    case["expected"]["response"] = {
        "task_type": "conversation",
        "status": "completed",
        "selected_capabilities": ["text_generation"],
        "error_code": None,
    }
    case["capabilities"] = [{
        "id": "text_generation",
        "implemented": True,
        "available": True,
        "adapter": True,
    }]

    parse_dataset(value)


@pytest.mark.parametrize(
    "contradiction",
    [
        "unsupported-classification-completed",
        "completed-with-error-code",
        "error-without-code",
        "unsupported-response-selects-capability",
        "error-response-selects-capability",
        "classification-response-task-mismatch",
        "classification-status-mismatch",
        "completed-selects-wrong-capability",
        "unavailable-selects-capability",
        "missing-adapter-selects-capability",
        "unavailable-configured-available",
        "missing-adapter-configured-present",
        "unsupported-error-on-error-response",
        "adapter-error-without-adapter",
    ],
)
def test_semantically_contradictory_expected_outcomes_are_rejected(
    contradiction: str,
) -> None:
    value = json.loads(
        (_ROOT / "tests/data/intelligence_eval/milestone4a_v1.json")
        .read_text(encoding="utf-8")
    )
    case = value["cases"][0]
    response = case["expected"]["response"]
    if contradiction == "unsupported-classification-completed":
        case["expected"]["classification"].update(
            {"task_type": "unsupported", "status": "unsupported"}
        )
        response.update({
            "task_type": "unsupported",
            "status": "completed",
            "selected_capabilities": [],
            "error_code": None,
        })
    elif contradiction == "completed-with-error-code":
        response["error_code"] = "ADAPTER_FAILURE"
    elif contradiction == "error-without-code":
        response.update({
            "status": "error",
            "selected_capabilities": [],
            "error_code": None,
        })
    elif contradiction == "unsupported-response-selects-capability":
        case["expected"]["classification"].update(
            {"task_type": "unsupported", "status": "unsupported"}
        )
        response.update({
            "task_type": "unsupported",
            "status": "unsupported",
            "selected_capabilities": ["language_lookup"],
            "error_code": "UNSUPPORTED_TASK",
        })
    elif contradiction == "error-response-selects-capability":
        response.update({
            "status": "error",
            "selected_capabilities": ["language_lookup"],
            "error_code": "ADAPTER_FAILURE",
        })
    elif contradiction == "classification-response-task-mismatch":
        response["task_type"] = "conversation"
    elif contradiction == "classification-status-mismatch":
        case["expected"]["classification"]["status"] = "unsupported"
    elif contradiction == "completed-selects-wrong-capability":
        response["selected_capabilities"] = ["text_generation"]
    elif contradiction == "unavailable-selects-capability":
        value["cases"][5]["expected"]["response"][
            "selected_capabilities"
        ] = ["provider_status"]
    elif contradiction == "missing-adapter-selects-capability":
        value["cases"][6]["expected"]["response"][
            "selected_capabilities"
        ] = ["provider_status"]
    elif contradiction == "unavailable-configured-available":
        value["cases"][5]["capabilities"][0].update({
            "implemented": True,
            "available": True,
            "adapter": True,
        })
    elif contradiction == "missing-adapter-configured-present":
        value["cases"][6]["capabilities"][0]["adapter"] = True
    elif contradiction == "unsupported-error-on-error-response":
        response.update({
            "status": "error",
            "selected_capabilities": [],
            "error_code": "UNSUPPORTED_TASK",
        })
    elif contradiction == "adapter-error-without-adapter":
        value["cases"][6]["expected"]["response"].update({
            "error_code": "ADAPTER_FAILURE",
        })

    with pytest.raises(DatasetSchemaError):
        parse_dataset(value)


def test_invalid_capability_state_is_rejected() -> None:
    value = json.loads(
        (_ROOT / "tests/data/intelligence_eval/milestone4a_v1.json")
        .read_text(encoding="utf-8")
    )
    value["cases"][0]["capabilities"][0]["available"] = True
    value["cases"][0]["capabilities"][0]["implemented"] = False

    with pytest.raises(DatasetSchemaError):
        parse_dataset(value)


def test_invalid_error_code_is_rejected_without_echoing_its_value() -> None:
    value = json.loads(
        (_ROOT / "tests/data/intelligence_eval/milestone4a_v1.json")
        .read_text(encoding="utf-8")
    )
    sentinel = "PRIVATE_DATASET_ERROR_SENTINEL_519"
    value["cases"][0]["expected"]["response"]["error_code"] = sentinel

    with pytest.raises(DatasetSchemaError) as error:
        parse_dataset(value)

    assert sentinel not in str(error.value)


def test_dataset_file_rejects_malformed_json(tmp_path: Path) -> None:
    dataset_path = tmp_path / "invalid.json"
    dataset_path.write_text("{", encoding="utf-8")

    with pytest.raises(DatasetSchemaError, match="not valid JSON"):
        load_dataset(dataset_path)


def test_dataset_file_rejects_duplicate_fields_and_invalid_encoding(
    tmp_path: Path,
) -> None:
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(
        '{"schema_version":1,"schema_version":1}',
        encoding="utf-8",
    )
    with pytest.raises(DatasetSchemaError, match="duplicate fields"):
        load_dataset(duplicate_path)

    encoding_path = tmp_path / "encoding.json"
    encoding_path.write_bytes(b"\xff")
    with pytest.raises(DatasetSchemaError, match="could not be read"):
        load_dataset(encoding_path)


@pytest.mark.asyncio
async def test_cli_dataset_loading_failure_suppresses_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "P4A_DATASET_LOAD_CREDENTIAL_SENTINEL_529"

    def fail_load(path):
        raise DatasetSchemaError(secret)

    monkeypatch.setattr(evaluation_cli, "load_dataset", fail_load)
    return_code = await evaluation_cli._evaluate(
        argparse.Namespace(dataset=None, repeats=1, warmup=0)
    )
    captured = capsys.readouterr()

    assert return_code == 2
    assert secret not in captured.out
    assert secret not in captured.err
    assert captured.err == (
        "Dataset loading or validation failed; details suppressed.\n"
    )


@pytest.mark.asyncio
async def test_every_benchmark_case_matches_its_expected_outcome() -> None:
    result = await run_evaluation(
        load_dataset(),
        repetitions=3,
        warmup_runs=1,
    )
    report = build_report(result)

    assert report["failures"] == []
    assert report["metrics"]["task_classification"]["accuracy"] == 1.0
    assert report["metrics"]["classification_status"]["accuracy"] == 1.0
    assert report["metrics"]["capability_selection"]["exact_match"]["accuracy"] == 1.0
    assert report["metrics"]["unsupported_handling"]["rate"] == 1.0
    assert report["metrics"]["capability_unavailable_handling"]["rate"] == 1.0
    assert report["metrics"]["missing_adapter_handling"]["rate"] == 1.0


def test_metric_formulas_and_confusion_matrix_are_hand_calculable() -> None:
    runs = (
        _case(
            "metric-conversation",
            "conversation",
            "default",
            ("text_generation",),
            "completed",
            None,
            "conversation",
            "default",
            ("text_generation",),
            "completed",
            None,
        ),
        _case(
            "metric-language",
            "language_lookup",
            "default",
            ("language_lookup",),
            "completed",
            None,
            "conversation",
            "default",
            ("text_generation",),
            "completed",
            None,
        ),
        _case(
            "metric-unsupported",
            "unsupported",
            "unsupported",
            (),
            "unsupported",
            "UNSUPPORTED_TASK",
            "unsupported",
            "unsupported",
            (),
            "unsupported",
            "UNSUPPORTED_TASK",
        ),
    )
    result = EvaluationResult(
        dataset_id="metric-test",
        schema_version=1,
        repetitions=1,
        warmup_runs=0,
        elapsed_ns=3,
        cases=runs,
    )

    metrics = calculate_metrics(result)

    assert metrics["task_classification"] == {
        "correct": 2,
        "total": 3,
        "accuracy": 2 / 3,
    }
    assert metrics["classification_status"]["accuracy"] == 1.0
    assert metrics["capability_selection"]["exact_match"] == {
        "correct": 2,
        "total": 3,
        "accuracy": 2 / 3,
    }
    assert metrics["capability_selection"]["micro"] == {
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 1,
    }
    assert metrics["per_task"]["conversation"]["precision"] == 0.5
    assert metrics["per_task"]["conversation"]["recall"] == 1.0
    assert metrics["per_task"]["conversation"]["f1"] == pytest.approx(2 / 3)
    assert metrics["per_task"]["language_lookup"]["f1"] == 0.0
    assert metrics["per_task"]["provider_status"]["f1"] is None
    assert metrics["macro_f1"] == pytest.approx(5 / 9)
    matrix = metrics["confusion_matrix"]["rows_true_columns_predicted"]
    assert matrix["conversation"]["conversation"] == 1
    assert matrix["language_lookup"]["conversation"] == 1
    assert matrix["unsupported"]["unsupported"] == 1
    assert matrix["provider_status"]["provider_status"] == 0


def test_unsupported_availability_and_missing_adapter_metrics() -> None:
    runs = (
        _case(
            "unsupported",
            "unsupported",
            "unsupported",
            (),
            "unsupported",
            "UNSUPPORTED_TASK",
            "unsupported",
            "unsupported",
            (),
            "unsupported",
            "UNSUPPORTED_TASK",
        ),
        _case(
            "supported-false-positive",
            "conversation",
            "default",
            ("text_generation",),
            "completed",
            None,
            "unsupported",
            "unsupported",
            (),
            "unsupported",
            "UNSUPPORTED_TASK",
        ),
        _case(
            "unavailable",
            "provider_status",
            "default",
            (),
            "error",
            "CAPABILITY_UNAVAILABLE",
            "provider_status",
            "default",
            (),
            "error",
            "CAPABILITY_UNAVAILABLE",
        ),
        _case(
            "missing-adapter",
            "provider_status",
            "default",
            (),
            "error",
            "ADAPTER_UNAVAILABLE",
            "provider_status",
            "default",
            (),
            "error",
            "ADAPTER_UNAVAILABLE",
        ),
    )
    result = EvaluationResult(
        dataset_id="metric-test",
        schema_version=1,
        repetitions=1,
        warmup_runs=0,
        elapsed_ns=1,
        cases=runs,
    )

    metrics = calculate_metrics(result)

    assert metrics["unsupported_handling"]["correct"] == 1
    assert metrics["unsupported_handling"]["total"] == 1
    assert metrics["false_unsupported"]["incorrect"] == 1
    assert metrics["false_unsupported"]["supported_total"] == 3
    assert metrics["capability_unavailable_handling"]["rate"] == 1.0
    assert metrics["missing_adapter_handling"]["rate"] == 1.0


def test_undefined_metrics_are_distinct_from_zero_scores() -> None:
    run = _case(
        "empty-selection",
        "conversation",
        "default",
        (),
        "completed",
        None,
        "conversation",
        "default",
        (),
        "completed",
        None,
    )
    result = EvaluationResult(
        dataset_id="empty-selection-test",
        schema_version=1,
        repetitions=1,
        warmup_runs=0,
        elapsed_ns=0,
        cases=(run,),
    )

    metrics = calculate_metrics(result)

    assert metrics["capability_selection"]["exact_match"]["accuracy"] == 1.0
    assert metrics["capability_selection"]["micro"] == {
        "precision": None,
        "recall": None,
        "f1": None,
        "true_positive": 0,
        "false_positive": 0,
        "false_negative": 0,
    }
    assert metrics["capability_selection"]["per_capability"] == {}
    assert metrics["per_task"]["provider_status"]["precision"] is None
    assert metrics["per_task"]["provider_status"]["recall"] is None
    assert metrics["per_task"]["provider_status"]["f1"] is None
    assert metrics["macro_f1"] == 1.0
    assert metrics["unsupported_handling"]["rate"] is None
    assert metrics["capability_unavailable_handling"]["rate"] is None
    assert metrics["missing_adapter_handling"]["rate"] is None
    conventions = build_report(result)["metric_conventions"]
    assert conventions["undefined_value"] is None
    assert "classes absent from both are excluded" in conventions["macro_f1"]
    assert "null when no capability is expected or selected" in conventions[
        "capability_metrics"
    ]


def test_zero_case_metrics_are_reported_as_undefined() -> None:
    result = EvaluationResult(
        dataset_id="empty-metrics-test",
        schema_version=1,
        repetitions=1,
        warmup_runs=0,
        elapsed_ns=0,
        cases=(),
    )

    metrics = calculate_metrics(result)
    report = build_report(result)

    assert metrics["task_classification"]["accuracy"] is None
    assert metrics["classification_status"]["accuracy"] is None
    assert metrics["macro_f1"] is None
    assert metrics["capability_selection"]["exact_match"]["accuracy"] is None
    assert metrics["capability_selection"]["micro"]["f1"] is None
    assert metrics["unsupported_handling"]["rate"] is None
    assert metrics["false_unsupported"]["rate"] is None
    assert metrics["capability_unavailable_handling"]["rate"] is None
    assert metrics["missing_adapter_handling"]["rate"] is None
    assert metrics["decision_consistency"]["classification"]["rate"] is None
    assert report["performance"]["classifier"]["median_ns"] is None
    assert report["performance"]["classifier"]["p95_ns"] is None
    assert report["performance"]["evaluation"]["cases_per_second"] is None
@pytest.mark.asyncio
async def test_unavailable_capabilities_never_invoke_an_adapter() -> None:
    result = await run_evaluation(
        load_dataset(),
        repetitions=2,
        warmup_runs=1,
    )
    by_id = {run.case.case_id: run for run in result.cases}

    assert by_id["unavailable-capability"].adapter_invocations == 0
    assert by_id["missing-adapter"].adapter_invocations == 0
    assert by_id["unsupported-action"].adapter_invocations == 0


@pytest.mark.asyncio
async def test_decisions_are_repeatable_and_performance_is_reported() -> None:
    result = await run_evaluation(
        load_dataset(),
        repetitions=5,
        warmup_runs=1,
    )
    report = build_report(result)

    assert report["metrics"]["decision_consistency"]["classification"]["rate"] == 1.0
    assert report["metrics"]["decision_consistency"]["response"]["rate"] == 1.0
    assert report["performance"]["classifier"]["samples"] == 40
    assert report["performance"]["orchestration_with_offline_adapters"]["samples"] == 40
    assert report["performance"]["classifier"]["median_ns"] >= 0
    assert report["performance"]["classifier"]["p95_ns"] >= 0
    assert report["performance"]["evaluation"]["cases_per_second"] > 0


@pytest.mark.asyncio
async def test_report_omits_raw_input_reasons_and_response_content() -> None:
    dataset = load_dataset()
    case = dataset.cases[2]
    sentinel = "PRIVATE_BENCHMARK_INPUT_SENTINEL_482"
    private_case = EvaluationCase(
        case_id=case.case_id,
        category=case.category,
        input=CaseInput(sentinel, case.input.explicit_task_type),
        capabilities=case.capabilities,
        expected=case.expected,
    )
    private_dataset = EvaluationDataset(
        dataset_id=dataset.dataset_id,
        schema_version=dataset.schema_version,
        cases=(private_case,),
    )
    result = await run_evaluation(
        private_dataset,
        repetitions=1,
        warmup_runs=0,
    )

    report_text = render_json_report(result)

    assert sentinel not in report_text
    assert "reason" not in report_text
    assert "fixed evaluation response" not in report_text


@pytest.mark.asyncio
async def test_execution_exception_text_is_suppressed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "P4A_EXECUTION_CREDENTIAL_SENTINEL_613"
    dataset = load_dataset()
    monkeypatch.setattr(evaluation_cli, "load_dataset", lambda path: dataset)

    def fail_with_sensitive_text(self, text, explicit_task_type=None):
        raise RuntimeError(secret)

    monkeypatch.setattr(
        runner.DeterministicTaskClassifier,
        "classify",
        fail_with_sensitive_text,
    )
    return_code = await evaluation_cli._evaluate(
        argparse.Namespace(dataset=None, repeats=1, warmup=0)
    )
    captured = capsys.readouterr()

    assert return_code == 1
    assert secret not in captured.out
    assert secret not in captured.err
    assert captured.err == "Evaluation execution failed; details suppressed.\n"


def test_cli_request_construction_failure_suppresses_credential_input(
    tmp_path: Path,
) -> None:
    sentinel = "P4A_REQUEST_CREDENTIAL_SENTINEL_782"
    dataset_value = json.loads(
        (_ROOT / "tests/data/intelligence_eval/milestone4a_v1.json")
        .read_text(encoding="utf-8")
    )
    dataset_value["cases"][0]["input"]["text"] = f"password={sentinel}"
    dataset_path = tmp_path / "invalid-input.json"
    dataset_path.write_text(json.dumps(dataset_value), encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "backend.app.intelligence.evaluation",
            "--dataset",
            str(dataset_path),
            "--repeats",
            "1",
            "--warmup",
            "0",
        ],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert sentinel not in completed.stdout
    assert sentinel not in completed.stderr
    assert completed.stderr == (
        "Evaluation request construction failed; details suppressed.\n"
    )


@pytest.mark.asyncio
async def test_cli_report_generation_failure_suppresses_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "P4A_REPORT_CREDENTIAL_SENTINEL_914"
    dataset = load_dataset()
    monkeypatch.setattr(evaluation_cli, "load_dataset", lambda path: dataset)

    def fail_report(result):
        raise RuntimeError(secret)

    monkeypatch.setattr(evaluation_cli, "render_json_report", fail_report)
    return_code = await evaluation_cli._evaluate(
        argparse.Namespace(dataset=None, repeats=1, warmup=0)
    )
    captured = capsys.readouterr()

    assert return_code == 1
    assert secret not in captured.out
    assert secret not in captured.err
    assert captured.err == (
        "Evaluation report generation failed; details suppressed.\n"
    )


def test_cli_runs_offline_and_emits_machine_readable_report() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "backend.app.intelligence.evaluation",
            "--repeats",
            "2",
            "--warmup",
            "0",
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["dataset"]["id"] == "milestone4a_v1"
    assert report["run"]["cases"] == 8
    assert report["failures"] == []
    assert "Irrelevant text" not in completed.stdout
    assert "Send an email for me" not in completed.stdout


def test_sync_runner_rejects_invalid_repeat_counts() -> None:
    dataset = load_dataset()
    with pytest.raises(ValueError, match="repetitions"):
        asyncio.run(run_evaluation(dataset, repetitions=0))
