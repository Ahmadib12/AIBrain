import json

from backend.app.intelligence.evaluation.metrics import (
    calculate_metrics,
    calculate_performance,
)
from backend.app.intelligence.evaluation.runner import EvaluationResult


def build_report(result: EvaluationResult) -> dict:
    cases = []
    failures = []
    for run in result.cases:
        expected_classification = {
            "task_type": run.expected_classification.task_type,
            "status": run.expected_classification.status,
        }
        expected_response = {
            "task_type": run.expected_response.task_type,
            "status": run.expected_response.status,
            "selected_capabilities": list(
                run.expected_response.selected_capabilities
            ),
            "error_code": run.expected_response.error_code,
        }
        actual_classification = {
            "task_type": run.actual_classification.task_type,
            "status": run.actual_classification.status,
            "confidence": run.actual_classification.confidence,
        }
        actual_response = {
            "task_type": run.actual_response.task_type,
            "status": run.actual_response.status,
            "selected_capabilities": list(
                run.actual_response.selected_capabilities
            ),
            "error_code": run.actual_response.error_code,
        }
        checks = {
            "classification_task_type": (
                expected_classification["task_type"]
                == actual_classification["task_type"]
            ),
            "classification_status": (
                expected_classification["status"]
                == actual_classification["status"]
            ),
            "response_task_type": (
                expected_response["task_type"]
                == actual_response["task_type"]
            ),
            "response_status": (
                expected_response["status"] == actual_response["status"]
            ),
            "selected_capabilities": (
                set(expected_response["selected_capabilities"])
                == set(actual_response["selected_capabilities"])
            ),
            "error_code": (
                expected_response["error_code"] == actual_response["error_code"]
            ),
            "classification_consistency": all(
                decision == run.classification_runs[0]
                for decision in run.classification_runs
            ),
            "response_consistency": all(
                decision == run.response_runs[0]
                for decision in run.response_runs
            ),
        }
        failed_checks = [
            check_name
            for check_name, passed in checks.items()
            if not passed
        ]
        case_report = {
            "id": run.case.case_id,
            "category": run.case.category,
            "expected": {
                "classification": expected_classification,
                "response": expected_response,
            },
            "actual": {
                "classification": actual_classification,
                "response": actual_response,
            },
            "checks": checks,
            "failed_checks": failed_checks,
            "adapter_invocations": run.adapter_invocations,
        }
        cases.append(case_report)
        if failed_checks:
            failures.append({
                "id": run.case.case_id,
                "failed_checks": failed_checks,
            })

    return {
        "dataset": {
            "id": result.dataset_id,
            "schema_version": result.schema_version,
        },
        "run": {
            "cases": len(result.cases),
            "repetitions": result.repetitions,
            "warmup_runs": result.warmup_runs,
        },
        "metric_conventions": {
            "undefined_value": None,
            "zero_denominator": (
                "Ratios with a zero denominator are null, not zero."
            ),
            "macro_f1": (
                "Arithmetic mean over task classes with expected support or "
                "predictions; classes absent from both are excluded."
            ),
            "capability_metrics": (
                "Exact match counts two empty selection sets as equal. "
                "Micro precision, recall, and F1 are null when no capability "
                "is expected or selected. Per-capability metrics are listed "
                "only for capabilities expected or selected at least once."
            ),
        },
        "metrics": calculate_metrics(result),
        "performance": calculate_performance(result),
        "failures": failures,
        "cases": cases,
    }


def render_json_report(result: EvaluationResult) -> str:
    return json.dumps(build_report(result), indent=2, sort_keys=True)
