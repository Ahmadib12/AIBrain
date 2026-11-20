from math import ceil
from statistics import median
from typing import Iterable

from backend.app.intelligence.evaluation.runner import (
    EvaluationResult,
)


_TASK_TYPES = (
    "conversation",
    "language_lookup",
    "provider_status",
    "unsupported",
)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(true_positive: int, false_positive: int, false_negative: int) -> float | None:
    denominator = 2 * true_positive + false_positive + false_negative
    return 2 * true_positive / denominator if denominator else None


def _classification_metrics(result: EvaluationResult) -> dict:
    runs = result.cases
    total = len(runs)
    correct = sum(
        run.actual_classification.task_type
        == run.expected_classification.task_type
        for run in runs
    )
    status_correct = sum(
        run.actual_classification.status == run.expected_classification.status
        for run in runs
    )
    matrix = {
        expected: {predicted: 0 for predicted in _TASK_TYPES}
        for expected in _TASK_TYPES
    }
    for run in runs:
        matrix[run.expected_classification.task_type][
            run.actual_classification.task_type
        ] += 1

    per_task: dict[str, dict[str, float | int | None]] = {}
    for task_type in _TASK_TYPES:
        true_positive = matrix[task_type][task_type]
        false_positive = sum(
            matrix[other][task_type]
            for other in _TASK_TYPES
            if other != task_type
        )
        false_negative = sum(
            matrix[task_type][other]
            for other in _TASK_TYPES
            if other != task_type
        )
        support = sum(matrix[task_type].values())
        predicted = sum(
            matrix[other][task_type]
            for other in _TASK_TYPES
        )
        per_task[task_type] = {
            "support": support,
            "predicted": predicted,
            "precision": _ratio(true_positive, true_positive + false_positive),
            "recall": _ratio(true_positive, true_positive + false_negative),
            "f1": _f1(true_positive, false_positive, false_negative),
        }
    observed_f1 = [
        metric["f1"]
        for metric in per_task.values()
        if metric["support"] or metric["predicted"]
    ]
    macro_f1 = (
        sum(value for value in observed_f1 if value is not None)
        / len(observed_f1)
        if observed_f1
        else None
    )
    return {
        "task_classification": {
            "correct": correct,
            "total": total,
            "accuracy": _ratio(correct, total),
        },
        "classification_status": {
            "correct": status_correct,
            "total": total,
            "accuracy": _ratio(status_correct, total),
        },
        "per_task": per_task,
        "macro_f1": macro_f1,
        "confusion_matrix": {
            "labels": list(_TASK_TYPES),
            "rows_true_columns_predicted": matrix,
        },
    }


def _capability_metrics(result: EvaluationResult) -> dict:
    exact_matches = 0
    true_positive = false_positive = false_negative = 0
    per_capability_counts: dict[str, list[int]] = {}
    for run in result.cases:
        expected = set(run.expected_response.selected_capabilities)
        actual = set(run.actual_response.selected_capabilities)
        exact_matches += expected == actual
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
        for capability_id in expected | actual:
            counts = per_capability_counts.setdefault(capability_id, [0, 0, 0])
            counts[0] += capability_id in expected and capability_id in actual
            counts[1] += capability_id in actual and capability_id not in expected
            counts[2] += capability_id in expected and capability_id not in actual

    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    f1 = _f1(true_positive, false_positive, false_negative)
    per_capability = {}
    for capability_id, (tp, fp, fn) in sorted(per_capability_counts.items()):
        per_capability[capability_id] = {
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "f1": _f1(tp, fp, fn),
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
        }
    return {
        "exact_match": {
            "correct": exact_matches,
            "total": len(result.cases),
            "accuracy": _ratio(exact_matches, len(result.cases)),
        },
        "micro": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
        },
        "per_capability": per_capability,
    }


def _outcome_rate(
    correct: int,
    total: int,
) -> dict[str, int | float | None]:
    return {
        "correct": correct,
        "total": total,
        "rate": _ratio(correct, total),
    }


def _handling_metrics(result: EvaluationResult) -> dict:
    unsupported_runs = [
        run
        for run in result.cases
        if run.expected_classification.task_type == "unsupported"
    ]
    supported_runs = [
        run
        for run in result.cases
        if run.expected_classification.task_type != "unsupported"
    ]
    unsupported_correct = sum(
        run.actual_response.task_type == "unsupported"
        and run.actual_response.status == "unsupported"
        and run.actual_response.error_code == "UNSUPPORTED_TASK"
        and not run.actual_response.selected_capabilities
        for run in unsupported_runs
    )
    false_unsupported = sum(
        run.actual_response.status == "unsupported"
        for run in supported_runs
    )

    unavailable_runs = [
        run
        for run in result.cases
        if run.expected_response.error_code == "CAPABILITY_UNAVAILABLE"
    ]
    missing_adapter_runs = [
        run
        for run in result.cases
        if run.expected_response.error_code == "ADAPTER_UNAVAILABLE"
    ]
    unavailable_correct = sum(
        run.actual_response.task_type == run.expected_response.task_type
        and run.actual_response.status == "error"
        and run.actual_response.error_code == "CAPABILITY_UNAVAILABLE"
        and not run.actual_response.selected_capabilities
        and run.adapter_invocations == 0
        for run in unavailable_runs
    )
    missing_adapter_correct = sum(
        run.actual_response.task_type == run.expected_response.task_type
        and run.actual_response.status == "error"
        and run.actual_response.error_code == "ADAPTER_UNAVAILABLE"
        and not run.actual_response.selected_capabilities
        and run.adapter_invocations == 0
        for run in missing_adapter_runs
    )
    return {
        "unsupported_handling": _outcome_rate(
            unsupported_correct,
            len(unsupported_runs),
        ),
        "false_unsupported": {
            "incorrect": false_unsupported,
            "supported_total": len(supported_runs),
            "rate": _ratio(false_unsupported, len(supported_runs)),
        },
        "capability_unavailable_handling": _outcome_rate(
            unavailable_correct,
            len(unavailable_runs),
        ),
        "missing_adapter_handling": _outcome_rate(
            missing_adapter_correct,
            len(missing_adapter_runs),
        ),
    }


def _consistency_metrics(result: EvaluationResult) -> dict:
    classifier_consistent = sum(
        all(
            decision == run.classification_runs[0]
            for decision in run.classification_runs
        )
        for run in result.cases
    )
    response_consistent = sum(
        all(
            decision == run.response_runs[0]
            for decision in run.response_runs
        )
        for run in result.cases
    )
    total = len(result.cases)
    return {
        "classification": _outcome_rate(classifier_consistent, total),
        "response": _outcome_rate(response_consistent, total),
    }


def calculate_metrics(result: EvaluationResult) -> dict:
    return {
        **_classification_metrics(result),
        "capability_selection": _capability_metrics(result),
        **_handling_metrics(result),
        "decision_consistency": _consistency_metrics(result),
    }


def _timing_summary(samples: Iterable[int]) -> dict[str, int | None]:
    values = sorted(samples)
    if not values:
        return {
            "samples": 0,
            "median_ns": None,
            "p95_ns": None,
        }
    p95_index = max(0, ceil(0.95 * len(values)) - 1)
    return {
        "samples": len(values),
        "median_ns": int(median(values)),
        "p95_ns": values[p95_index],
    }


def calculate_performance(result: EvaluationResult) -> dict:
    classifier_samples = [
        sample
        for run in result.cases
        for sample in run.classifier_timings_ns
    ]
    orchestration_samples = [
        sample
        for run in result.cases
        for sample in run.orchestration_timings_ns
    ]
    measured_cases = len(result.cases) * result.repetitions
    return {
        "classifier": _timing_summary(classifier_samples),
        "orchestration_with_offline_adapters": _timing_summary(
            orchestration_samples
        ),
        "evaluation": {
            "elapsed_ns": result.elapsed_ns,
            "measured_cases": measured_cases,
            "cases_per_second": (
                measured_cases * 1_000_000_000 / result.elapsed_ns
                if result.elapsed_ns > 0 and measured_cases > 0
                else None
            ),
        },
    }
