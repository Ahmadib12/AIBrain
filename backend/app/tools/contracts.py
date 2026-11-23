import copy
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ToolRisk(str, Enum):
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    CONSEQUENTIAL = "consequential"


@dataclass(frozen=True)
class ToolContract:
    tool_id: str
    name: str
    description: str
    risk: ToolRisk
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    version: int = 1

    def __post_init__(self) -> None:
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version < 1
        ):
            raise ValueError("Tool contract version must be a positive integer")


def contract_fingerprint(contract: ToolContract) -> str:
    canonical_contract = {
        "tool_id": contract.tool_id,
        "name": contract.name,
        "description": contract.description,
        "risk": contract.risk.value,
        "version": contract.version,
        "input_schema": contract.input_schema,
        "output_schema": contract.output_schema,
    }

    canonical_json = json.dumps(
        canonical_contract,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(canonical_json).hexdigest()


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolContract] = {}

    def register(self, contract: ToolContract) -> None:
        if contract.tool_id in self._tools:
            raise ValueError("Tool is already registered")
        self._tools[contract.tool_id] = copy.deepcopy(contract)

    def get(self, tool_id: str) -> ToolContract | None:
        contract = self._tools.get(tool_id)
        return copy.deepcopy(contract) if contract is not None else None

    def list(self) -> tuple[ToolContract, ...]:
        return tuple(
            copy.deepcopy(contract)
            for contract in sorted(
                self._tools.values(),
                key=lambda contract: contract.tool_id,
            )
        )
