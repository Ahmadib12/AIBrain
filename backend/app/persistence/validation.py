import json
import math
import re
from typing import Any


PERSONAL_PAYLOAD_MAX_BYTES = 64 * 1024
PERSONAL_PAYLOAD_MAX_DEPTH = 6
PERSONAL_PAYLOAD_MAX_ITEMS = 100

_SENSITIVE_KEY = re.compile(
    r"(api[_-]?key|password|passwd|secret|credential|private[_-]?key"
    r"|authorization|bearer|token)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|-----begin private key-----"
    r"|(?:api[_-]?key|password|passwd|secret|credential"
    r"|private[_-]?key|authorization|bearer|token)\s*[:=])",
)


def validate_personal_payload(value: Any) -> None:
    def walk(item: Any, depth: int) -> None:
        if depth > PERSONAL_PAYLOAD_MAX_DEPTH:
            raise ValueError("Personal payload nesting is too deep")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("Personal payload cannot contain non-finite numbers")
            return
        if isinstance(item, str):
            if len(item) > 16_384:
                raise ValueError("Personal payload string is too large")
            if _SENSITIVE_VALUE.search(item):
                raise ValueError("Sensitive personal values are not allowed")
            return
        if isinstance(item, list):
            if len(item) > PERSONAL_PAYLOAD_MAX_ITEMS:
                raise ValueError("Personal payload collection is too large")
            for child in item:
                walk(child, depth + 1)
            return
        if isinstance(item, dict):
            if len(item) > PERSONAL_PAYLOAD_MAX_ITEMS:
                raise ValueError("Personal payload collection is too large")
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 200:
                    raise ValueError("Personal payload key is invalid")
                if _SENSITIVE_KEY.search(key):
                    raise ValueError("Sensitive personal keys are not allowed")
                walk(child, depth + 1)
            return
        raise ValueError("Personal payload contains an unsupported value")

    walk(value, 0)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("Personal payload must be valid JSON") from error
    if len(encoded) > PERSONAL_PAYLOAD_MAX_BYTES:
        raise ValueError("Personal payload is too large")
