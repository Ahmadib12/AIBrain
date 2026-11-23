import math

import pytest

from backend.app.tools.validation import validate_tool_arguments


def test_valid_nested_object_and_array() -> None:
    schema = {
        "type": "object",
        "properties": {
            "profile": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
            "scores": {
                "type": "array",
                "items": {"type": "integer"},
                "maxItems": 3,
            },
        },
        "required": ["profile", "scores"],
        "additionalProperties": False,
    }

    validate_tool_arguments(
        schema,
        {"profile": {"name": "Ahmad"}, "scores": [10, 20]},
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"profile": {}, "scores": [10]},
        {"profile": {"name": "Ahmad", "admin": True}, "scores": [10]},
        {"profile": {"name": "Ahmad"}, "scores": [10, "bad"]},
        {"profile": {"name": "Ahmad"}, "scores": [1, 2, 3, 4]},
        {"profile": {"name": ""}, "scores": []},
        {"profile": {"name": "Ahmad"}, "scores": [], "extra": True},
    ],
)
def test_invalid_nested_arguments_are_rejected(arguments: dict) -> None:
    schema = {
        "type": "object",
        "properties": {
            "profile": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
            "scores": {
                "type": "array",
                "items": {"type": "integer"},
                "maxItems": 3,
            },
        },
        "required": ["profile", "scores"],
        "additionalProperties": False,
    }

    with pytest.raises(ValueError):
        validate_tool_arguments(schema, arguments)


def test_unsupported_schema_keywords_are_rejected() -> None:
    schema = {
        "type": "object",
        "properties": {
            "age": {"type": "integer", "minimum": 18},
        },
    }

    with pytest.raises(ValueError, match="Unsupported schema keyword"):
        validate_tool_arguments(schema, {"age": 20})


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    schema = {
        "type": "object",
        "properties": {"amount": {"type": "number"}},
        "required": ["amount"],
    }

    with pytest.raises(ValueError, match="finite"):
        validate_tool_arguments(schema, {"amount": value})


def test_boolean_is_not_accepted_as_integer() -> None:
    schema = {
        "type": "object",
        "properties": {"count": {"type": "integer"}},
    }

    with pytest.raises(ValueError, match="integer"):
        validate_tool_arguments(schema, {"count": True})


def test_invalid_schema_definition_is_rejected() -> None:
    schema = {
        "type": "object",
        "properties": {"name": {"type": "string", "maxLength": -1}},
    }

    with pytest.raises(ValueError, match="Invalid maxLength"):
        validate_tool_arguments(schema, {"name": "Ahmad"})
