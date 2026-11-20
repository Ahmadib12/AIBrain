from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any


_DATASET_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_CASE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_TASK_TYPES = frozenset({
    "conversation",
    "language_lookup",
    "provider_status",
    "unsupported",
})
_CLASSIFICATION_STATUSES = frozenset({
    "default",
    "explicit",
    "unsupported",
})
_RESPONSE_STATUSES = frozenset({
    "completed",
    "error",
    "unsupported",
})
_CAPABILITY_IDS = frozenset({
    "language_lookup",
    "provider_status",
    "text_generation",
})
_ERROR_CODES = frozenset({
    "ADAPTER_FAILURE",
    "ADAPTER_TIMEOUT",
    "ADAPTER_UNAVAILABLE",
    "CAPABILITY_UNAVAILABLE",
    "INTELLIGENCE_FAILURE",
    "INVALID_ADAPTER_RESULT",
    "INVALID_REQUEST",
    "LANGUAGE_NOT_FOUND",
    "UNSUPPORTED_TASK",
})
# Dataset schema v1 mirrors the current core: success selects its mapped,
# available adapter; error and unsupported responses select no capability.
_TASK_CAPABILITIES = {
    "conversation": "text_generation",
    "language_lookup": "language_lookup",
    "provider_status": "provider_status",
}
_EXPLICIT_TASK_TYPES = {
    "conversation": "conversation",
    "general": "conversation",
    "chat": "conversation",
    "language_lookup": "language_lookup",
    "language": "language_lookup",
    "provider_status": "provider_status",
    "providers": "provider_status",
    "unsupported": "unsupported",
}
# These request/API-level failures use UNSUPPORTED in the response even when
# the independent classifier projection has a supported task type.
_GENERIC_ERROR_CODES = frozenset({
    "INTELLIGENCE_FAILURE",
    "INVALID_REQUEST",
})
_ADAPTER_ERROR_CODES = frozenset({
    "ADAPTER_FAILURE",
    "ADAPTER_TIMEOUT",
    "INVALID_ADAPTER_RESULT",
})
_DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parents[4]
    / "tests"
    / "data"
    / "intelligence_eval"
    / "milestone4a_v1.json"
)


class DatasetSchemaError(ValueError):
    """Raised when an evaluation dataset does not match the supported schema."""


@dataclass(frozen=True)
class CaseInput:
    text: str
    explicit_task_type: str | None


@dataclass(frozen=True)
class CapabilitySetup:
    capability_id: str
    implemented: bool
    available: bool
    adapter: bool


@dataclass(frozen=True)
class ExpectedClassification:
    task_type: str
    status: str


@dataclass(frozen=True)
class ExpectedResponse:
    task_type: str
    status: str
    selected_capabilities: tuple[str, ...]
    error_code: str | None


@dataclass(frozen=True)
class ExpectedOutcome:
    classification: ExpectedClassification
    response: ExpectedResponse


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    category: str
    input: CaseInput
    capabilities: tuple[CapabilitySetup, ...]
    expected: ExpectedOutcome


@dataclass(frozen=True)
class EvaluationDataset:
    dataset_id: str
    schema_version: int
    cases: tuple[EvaluationCase, ...]


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        raise DatasetSchemaError(f"{path}: expected an object")
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DatasetSchemaError("dataset JSON contains duplicate fields")
        value[key] = item
    return value


def _keys(
    value: dict[str, Any],
    required: set[str],
    path: str,
) -> None:
    if set(value) != required:
        raise DatasetSchemaError(f"{path}: invalid fields")


def _string(
    value: Any,
    path: str,
    *,
    max_length: int,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or len(value) > max_length
        or (not allow_empty and not value.strip())
    ):
        raise DatasetSchemaError(f"{path}: invalid string")
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise DatasetSchemaError(f"{path}: expected a boolean")
    return value


def _enum(value: Any, choices: frozenset[str], path: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise DatasetSchemaError(f"{path}: invalid value")
    return value


def _parse_case(value: Any, index: int) -> EvaluationCase:
    path = f"cases[{index}]"
    case = _object(value, path)
    _keys(
        case,
        {"id", "category", "input", "capabilities", "expected"},
        path,
    )

    case_id = _string(case["id"], f"{path}.id", max_length=64)
    if not _CASE_ID_PATTERN.fullmatch(case_id):
        raise DatasetSchemaError(f"{path}.id: invalid identifier")

    category = _string(
        case["category"],
        f"{path}.category",
        max_length=64,
    )
    if not _DATASET_ID_PATTERN.fullmatch(category):
        raise DatasetSchemaError(f"{path}.category: invalid identifier")

    input_value = _object(case["input"], f"{path}.input")
    _keys(input_value, {"text", "task_type"}, f"{path}.input")
    text = _string(
        input_value["text"],
        f"{path}.input.text",
        max_length=100_000,
    )
    explicit_task_type = input_value["task_type"]
    if explicit_task_type is not None:
        explicit_task_type = _string(
            explicit_task_type,
            f"{path}.input.task_type",
            max_length=100,
        )

    capabilities_value = case["capabilities"]
    if not isinstance(capabilities_value, list):
        raise DatasetSchemaError(f"{path}.capabilities: expected an array")
    capabilities: list[CapabilitySetup] = []
    seen_capability_ids: set[str] = set()
    for capability_index, capability_value in enumerate(capabilities_value):
        capability_path = f"{path}.capabilities[{capability_index}]"
        capability = _object(capability_value, capability_path)
        _keys(
            capability,
            {"id", "implemented", "available", "adapter"},
            capability_path,
        )
        capability_id = _enum(
            capability["id"],
            _CAPABILITY_IDS,
            f"{capability_path}.id",
        )
        if capability_id in seen_capability_ids:
            raise DatasetSchemaError(
                f"{capability_path}: duplicate capability"
            )
        seen_capability_ids.add(capability_id)
        implemented = _boolean(
            capability["implemented"],
            f"{capability_path}.implemented",
        )
        available = _boolean(
            capability["available"],
            f"{capability_path}.available",
        )
        adapter = _boolean(
            capability["adapter"],
            f"{capability_path}.adapter",
        )
        if available and not implemented:
            raise DatasetSchemaError(
                f"{capability_path}: available capability must be implemented"
            )
        if adapter and not available:
            raise DatasetSchemaError(
                f"{capability_path}: adapter requires an available capability"
            )
        capabilities.append(CapabilitySetup(
            capability_id=capability_id,
            implemented=implemented,
            available=available,
            adapter=adapter,
        ))

    expected_value = _object(case["expected"], f"{path}.expected")
    _keys(
        expected_value,
        {"classification", "response"},
        f"{path}.expected",
    )
    classification_value = _object(
        expected_value["classification"],
        f"{path}.expected.classification",
    )
    _keys(
        classification_value,
        {"task_type", "status"},
        f"{path}.expected.classification",
    )
    expected_classification = ExpectedClassification(
        task_type=_enum(
            classification_value["task_type"],
            _TASK_TYPES,
            f"{path}.expected.classification.task_type",
        ),
        status=_enum(
            classification_value["status"],
            _CLASSIFICATION_STATUSES,
            f"{path}.expected.classification.status",
        ),
    )

    response_value = _object(
        expected_value["response"],
        f"{path}.expected.response",
    )
    _keys(
        response_value,
        {
            "task_type",
            "status",
            "selected_capabilities",
            "error_code",
        },
        f"{path}.expected.response",
    )
    selected_value = response_value["selected_capabilities"]
    if not isinstance(selected_value, list):
        raise DatasetSchemaError(
            f"{path}.expected.response.selected_capabilities: expected an array"
        )
    selected_capabilities = tuple(
        _enum(
            capability_id,
            _CAPABILITY_IDS,
            f"{path}.expected.response.selected_capabilities",
        )
        for capability_id in selected_value
    )
    if len(set(selected_capabilities)) != len(selected_capabilities):
        raise DatasetSchemaError(
            f"{path}.expected.response: duplicate selected capability"
        )
    error_code = response_value["error_code"]
    if error_code is not None:
        error_code = _enum(
            error_code,
            _ERROR_CODES,
            f"{path}.expected.response.error_code",
        )
    expected_response = ExpectedResponse(
        task_type=_enum(
            response_value["task_type"],
            _TASK_TYPES,
            f"{path}.expected.response.task_type",
        ),
        status=_enum(
            response_value["status"],
            _RESPONSE_STATUSES,
            f"{path}.expected.response.status",
        ),
        selected_capabilities=selected_capabilities,
        error_code=error_code,
    )
    parsed_case = EvaluationCase(
        case_id=case_id,
        category=category,
        input=CaseInput(
            text=text,
            explicit_task_type=explicit_task_type,
        ),
        capabilities=tuple(capabilities),
        expected=ExpectedOutcome(
            classification=expected_classification,
            response=expected_response,
        ),
    )
    _validate_expected_outcome(parsed_case, path)
    return parsed_case


def _validate_expected_outcome(
    case: EvaluationCase,
    path: str,
) -> None:
    classification = case.expected.classification
    response = case.expected.response
    explicit_task_type = case.input.explicit_task_type
    if explicit_task_type:
        normalized_explicit_type = (
            explicit_task_type.strip().lower().replace("-", "_")
        )
        expected_explicit_type = _EXPLICIT_TASK_TYPES.get(
            normalized_explicit_type,
            "unsupported",
        )
        if (
            classification.task_type != expected_explicit_type
            or (
                expected_explicit_type != "unsupported"
                and classification.status != "explicit"
            )
        ):
            raise DatasetSchemaError(
                f"{path}.expected.classification: does not match explicit task type"
            )

    is_unsupported = classification.task_type == "unsupported"
    if is_unsupported != (classification.status == "unsupported"):
        raise DatasetSchemaError(
            f"{path}.expected.classification: inconsistent task and status"
        )

    error_code = response.error_code
    selected = response.selected_capabilities
    if is_unsupported:
        if (
            response.task_type != "unsupported"
            or response.status != "unsupported"
            or error_code != "UNSUPPORTED_TASK"
            or selected
        ):
            raise DatasetSchemaError(
                f"{path}.expected: unsupported classification has an invalid response"
            )
        return

    if response.status == "unsupported":
        raise DatasetSchemaError(
            f"{path}.expected.response: supported classification cannot be unsupported"
        )

    if error_code not in _GENERIC_ERROR_CODES:
        if response.task_type != classification.task_type:
            raise DatasetSchemaError(
                f"{path}.expected.response: task type does not match classification"
            )
    elif response.task_type != "unsupported":
        raise DatasetSchemaError(
            f"{path}.expected.response: generic failure must use unsupported task type"
        )

    if response.status == "completed":
        if error_code is not None:
            raise DatasetSchemaError(
                f"{path}.expected.response: completed response cannot have an error code"
            )
        expected_capability = _TASK_CAPABILITIES[classification.task_type]
        if selected != (expected_capability,):
            raise DatasetSchemaError(
                f"{path}.expected.response: completed response must select its task capability"
            )
        capability = {
            item.capability_id: item
            for item in case.capabilities
        }.get(expected_capability)
        if capability is None or not capability.available or not capability.adapter:
            raise DatasetSchemaError(
                f"{path}.expected.response: completed response requires an available adapter"
            )
        return

    if response.status != "error" or error_code is None:
        raise DatasetSchemaError(
            f"{path}.expected.response: error response requires an error code"
        )
    if error_code == "UNSUPPORTED_TASK" or selected:
        raise DatasetSchemaError(
            f"{path}.expected.response: error response has contradictory outcome fields"
        )
    if error_code in _GENERIC_ERROR_CODES:
        return

    capability_id = _TASK_CAPABILITIES[classification.task_type]
    capability = {
        item.capability_id: item
        for item in case.capabilities
    }.get(capability_id)
    if error_code == "CAPABILITY_UNAVAILABLE":
        if capability is not None and capability.available:
            raise DatasetSchemaError(
                f"{path}.expected.response: unavailable capability is configured available"
            )
        return
    if error_code == "ADAPTER_UNAVAILABLE":
        if (
            capability is None
            or not capability.available
            or capability.adapter
        ):
            raise DatasetSchemaError(
                f"{path}.expected.response: missing adapter requires an available capability without an adapter"
            )
        return
    if error_code == "LANGUAGE_NOT_FOUND" and classification.task_type != "language_lookup":
        raise DatasetSchemaError(
            f"{path}.expected.response: language error requires language lookup"
        )
    if (
        error_code == "LANGUAGE_NOT_FOUND"
        or error_code in _ADAPTER_ERROR_CODES
    ) and (
        capability is None
        or not capability.available
        or not capability.adapter
    ):
        raise DatasetSchemaError(
            f"{path}.expected.response: adapter error requires an available adapter"
        )


def parse_dataset(value: Any) -> EvaluationDataset:
    root = _object(value, "dataset")
    _keys(root, {"schema_version", "dataset_id", "cases"}, "dataset")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise DatasetSchemaError("dataset.schema_version: unsupported version")
    dataset_id = _string(
        root["dataset_id"],
        "dataset.dataset_id",
        max_length=64,
    )
    if not _DATASET_ID_PATTERN.fullmatch(dataset_id):
        raise DatasetSchemaError("dataset.dataset_id: invalid identifier")
    cases_value = root["cases"]
    if not isinstance(cases_value, list) or not cases_value:
        raise DatasetSchemaError("dataset.cases: expected a non-empty array")
    cases = tuple(
        _parse_case(case_value, index)
        for index, case_value in enumerate(cases_value)
    )
    case_ids = [case.case_id for case in cases]
    if len(set(case_ids)) != len(case_ids):
        raise DatasetSchemaError("dataset.cases: duplicate case identifier")
    return EvaluationDataset(
        dataset_id=dataset_id,
        schema_version=1,
        cases=cases,
    )


def load_dataset(path: Path | None = None) -> EvaluationDataset:
    dataset_path = path or _DEFAULT_DATASET_PATH
    try:
        text = dataset_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise DatasetSchemaError("dataset file could not be read") from None
    try:
        value = json.loads(text, object_pairs_hook=_unique_json_object)
    except json.JSONDecodeError:
        raise DatasetSchemaError("dataset is not valid JSON") from None
    return parse_dataset(value)
