import json
import uuid
from datetime import datetime, timezone

import pytest

from backend.app.app_state import get_app_state
from backend.app.tools import (
    ToolContract,
    ToolExecutionGateway,
    ToolRegistry,
    ToolRisk,
)


def create_gateway():
    state = get_app_state()
    user_id = f"tool-validation-{uuid.uuid4()}"
    now = datetime.now(timezone.utc).isoformat()

    state.database.connect().execute(
        "INSERT INTO users "
        "(id, email, password_salt, password_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, f"{user_id}@example.com", "salt", "hash", now),
    )
    state.database.connect().commit()

    registry = ToolRegistry()
    registry.register(ToolContract(
        tool_id="echo",
        name="Echo",
        description="Test echo tool",
        risk=ToolRisk.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "maxLength": 4096},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema={"text": {"type": "string"}},
    ))

    return state, user_id, ToolExecutionGateway(registry, state.database)


def test_invalid_arguments_are_rejected_before_persistence() -> None:
    state, user_id, gateway = create_gateway()

    with pytest.raises(ValueError, match="must be a string"):
        gateway.propose(
            user_id,
            tool_id="echo",
            arguments={"text": 123},
        )

    row = state.database.connect().execute(
        "SELECT COUNT(*) AS total FROM tool_requests WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    assert row["total"] == 0


def test_invalid_persisted_arguments_are_rejected_before_claim() -> None:
    state, user_id, gateway = create_gateway()

    proposal = gateway.propose(
        user_id,
        tool_id="echo",
        arguments={"text": "valid initially"},
    )

    state.database.connect().execute(
        "UPDATE tool_requests SET arguments_json = ? "
        "WHERE id = ? AND user_id = ?",
        (json.dumps({"text": 123}), proposal["id"], user_id),
    )
    state.database.connect().commit()

    with pytest.raises(ValueError, match="must be a string"):
        gateway.execute(proposal, user_id=user_id)

    persisted = gateway._tool_requests.get(user_id, proposal["id"])

    assert persisted["status"] == "approved"
    assert persisted["consumed_at"] is None

def register_test_tool(gateway, *, tool_id: str, risk: ToolRisk) -> None:
    gateway.registry.register(ToolContract(
        tool_id=tool_id,
        name=f"Test {tool_id}",
        description="Test tool for risk-policy validation",
        risk=risk,
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "maxLength": 4096},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema={"text": {"type": "string"}},
    ))


def test_state_change_requires_confirmation_and_still_cannot_execute() -> None:
    state, user_id, gateway = create_gateway()
    register_test_tool(
        gateway,
        tool_id="state-change-test",
        risk=ToolRisk.STATE_CHANGE,
    )

    proposal = gateway.propose(
        user_id,
        tool_id="state-change-test",
        arguments={"text": "change requested"},
    )

    assert proposal["status"] == "pending"

    with pytest.raises(
        PermissionError,
        match="Human authorization is not implemented",
    ):
        gateway.confirm(user_id, proposal["id"])

    with pytest.raises(
        PermissionError,
        match="complete confirmation policy",
    ):
        gateway.execute(proposal, user_id=user_id)

    persisted = gateway._tool_requests.get(user_id, proposal["id"])
    assert persisted["status"] == "pending"
    assert persisted["consumed_at"] is None


def test_consequential_tool_is_rejected_before_persistence() -> None:
    state, user_id, gateway = create_gateway()
    register_test_tool(
        gateway,
        tool_id="consequential-test",
        risk=ToolRisk.CONSEQUENTIAL,
    )

    with pytest.raises(
        PermissionError,
        match="stronger authorization policy",
    ):
        gateway.propose(
            user_id,
            tool_id="consequential-test",
            arguments={"text": "high impact action"},
        )

    row = state.database.connect().execute(
        "SELECT COUNT(*) AS total FROM tool_requests WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    assert row["total"] == 0



def test_valid_schema_argument_tampering_is_rejected_before_execution():
    state, user_id, gateway = create_gateway()

    proposal = gateway.propose(
        user_id,
        tool_id="echo",
        arguments={"text": "original request"},
    )

    state.database.connect().execute(
        "UPDATE tool_requests SET arguments_json = ? WHERE id = ?",
        (json.dumps({"text": "different but valid"}), proposal["id"]),
    )
    state.database.connect().commit()

    with pytest.raises(PermissionError, match="changed after proposal"):
        gateway.execute(proposal, user_id=user_id)

    persisted = gateway._tool_requests.get(user_id, proposal["id"])
    assert persisted["status"] == "approved"
    assert persisted["consumed_at"] is None
