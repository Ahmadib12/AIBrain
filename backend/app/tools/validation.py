import math
from typing import Any


def _validate_value(
    schema: dict[str, Any],
    value: Any,
    path: str,
) -> None:
    if not isinstance(schema, dict):
        raise ValueError("Property schema must be an object")

    expected = schema.get("type")

    allowed = {
        "object": {"type", "properties", "required", "additionalProperties"},
        "array": {"type", "items", "maxItems"},
        "string": {"type", "maxLength", "minLength"},
        "integer": {"type"},
        "number": {"type"},
        "boolean": {"type"},
    }

    if expected not in allowed:
        raise ValueError(f"Unsupported schema type at {path}")

    if set(schema) - allowed[expected]:
        raise ValueError(f"Unsupported schema keyword at {path}")

    if expected == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object")

        properties = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", False)

        if not isinstance(properties, dict):
            raise ValueError("Invalid properties schema")
        if not isinstance(required, list):
            raise ValueError("Invalid required schema")
        if any(not isinstance(key, str) for key in properties):
            raise ValueError("Invalid property name")
        if any(not isinstance(key, str) for key in required):
            raise ValueError("Invalid required property")
        if len(required) != len(set(required)):
            raise ValueError("Duplicate required property")
        if any(key not in properties for key in required):
            raise ValueError("Required field is not defined")
        if not isinstance(additional, bool):
            raise ValueError("Invalid additionalProperties setting")

        if set(required) - value.keys():
            raise ValueError(f"Missing required field at {path}")

        if not additional and value.keys() - properties.keys():
            raise ValueError(f"Unexpected field at {path}")

        for key, item in value.items():
            if key in properties:
                _validate_value(properties[key], item, f"{path}.{key}")

    elif expected == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array")

        maximum = schema.get("maxItems")
        if maximum is not None:
            if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
                raise ValueError("Invalid maxItems schema")
            if len(value) > maximum:
                raise ValueError(f"{path} exceeds maxItems")

        if "items" in schema:
            for index, item in enumerate(value):
                _validate_value(schema["items"], item, f"{path}[{index}]")

    elif expected == "string":
        if not isinstance(value, str):
            raise ValueError(f"{path} must be a string")

        for keyword in ("minLength", "maxLength"):
            limit = schema.get(keyword)
            if limit is not None:
                if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                    raise ValueError(f"Invalid {keyword} schema")
                if keyword == "minLength" and len(value) < limit:
                    raise ValueError(f"{path} is shorter than minLength")
                if keyword == "maxLength" and len(value) > limit:
                    raise ValueError(f"{path} exceeds maxLength")

    elif expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{path} must be an integer")

    elif expected == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{path} must be a number")
        if not math.isfinite(value):
            raise ValueError(f"{path} must be finite")

    elif expected == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{path} must be a boolean")


def validate_tool_arguments(
    schema: dict[str, Any],
    arguments: dict[str, Any],
) -> None:
    """Validate tool arguments against the supported JSON Schema subset."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("Tool input schema must define an object")

    _validate_value(schema, arguments, "arguments")
