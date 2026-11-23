from datetime import datetime, timezone
import uuid

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.tools import ToolContract, ToolRegistry, ToolRisk
from backend.app.tools.contracts import contract_fingerprint
from backend.app.tools.runtime import ToolExecutionGateway


def create_gateway(tmp_path, contracts):
    database = Database(f"sqlite:///{tmp_path / 'gateway-boundary.db'}")
    user_id = f"gateway-boundary-{uuid.uuid4()}"
    with database.transaction():
        database.connect().execute(
            """
            INSERT INTO users (
                id, email, password_salt, password_hash, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                f"{user_id}@example.com",
                "test-salt",
                "test-hash",
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    registry = ToolRegistry()
    for contract in contracts:
        registry.register(contract)

    gateway = ToolExecutionGateway(registry, database)
    return database, user_id, gateway, ToolRequestRepository(database)


def read_only_echo_contract(*, description="Echo text"):
    return ToolContract(
        tool_id="echo",
        name="Echo",
        description=description,
        risk=ToolRisk.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 4096}},
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


def state_change_contract():
    return ToolContract(
        tool_id="send-message",
        name="Send message",
        description="Send a message to another person",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 100}},
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


def consequential_contract():
    return ToolContract(
        tool_id="transfer-funds",
        name="Transfer funds",
        description="Transfer money to another account",
        risk=ToolRisk.CONSEQUENTIAL,
        input_schema={
            "type": "object",
            "properties": {"amount": {"type": "integer", "minimum": 1}},
            "required": ["amount"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


def execution_attempt_count(database, request_id):
    return database.connect().execute(
        "SELECT COUNT(*) FROM tool_execution_attempts WHERE request_id = ?",
        (request_id,),
    ).fetchone()[0]


def test_passkey_approved_state_change_cannot_execute_through_gateway(tmp_path):
    contract = state_change_contract()
    database, user_id, gateway, requests = create_gateway(tmp_path, [contract])
    try:
        request = requests.create(
            user_id,
            tool_id=contract.tool_id,
            arguments={"text": "approved message"},
            status="approved",
            expires_at="2099-01-01T00:00:00+00:00",
            contract_fingerprint=contract_fingerprint(contract),
            authorization_policy="passkey",
        )

        with pytest.raises(
            PermissionError,
            match="complete confirmation policy",
        ):
            gateway.execute(
                {"id": request["id"], "user_id": user_id},
                user_id=user_id,
            )

        persisted = requests.get(user_id, request["id"])
        assert persisted["status"] == "approved"
        assert persisted["consumed_at"] is None
        assert execution_attempt_count(database, request["id"]) == 0
    finally:
        database.shutdown()


def test_read_only_request_cannot_use_passkey_execution_claim(tmp_path):
    contract = read_only_echo_contract()
    database, user_id, gateway, requests = create_gateway(tmp_path, [contract])
    try:
        proposal = gateway.propose(
            user_id,
            tool_id=contract.tool_id,
            arguments={"text": "read-only request"},
        )

        with pytest.raises(
            PermissionError,
            match="restricted to passkey-authorized requests",
        ):
            requests.claim_passkey_authorized_for_execution(
                user_id,
                proposal["id"],
                expected_contract_fingerprint=contract_fingerprint(contract),
            )

        persisted = requests.get(user_id, proposal["id"])
        assert persisted["status"] == "approved"
        assert persisted["consumed_at"] is None
        assert execution_attempt_count(database, proposal["id"]) == 0
    finally:
        database.shutdown()


def test_state_change_confirmation_remains_disabled_after_approval(tmp_path):
    contract = state_change_contract()
    database, user_id, gateway, requests = create_gateway(tmp_path, [contract])
    try:
        proposal = gateway.propose(
            user_id,
            tool_id=contract.tool_id,
            arguments={"text": "do not dispatch"},
        )
        assert proposal["status"] == "pending"

        with pytest.raises(
            PermissionError,
            match="Human authorization is not implemented",
        ):
            gateway.confirm(user_id, proposal["id"])

        persisted = requests.get(user_id, proposal["id"])
        assert persisted["status"] == "pending"
        assert persisted["consumed_at"] is None
        assert execution_attempt_count(database, proposal["id"]) == 0
    finally:
        database.shutdown()


def test_consequential_tool_is_rejected_before_request_persistence(tmp_path):
    contract = consequential_contract()
    database, user_id, gateway, _ = create_gateway(tmp_path, [contract])
    try:
        with pytest.raises(
            PermissionError,
            match="stronger authorization policy",
        ):
            gateway.propose(
                user_id,
                tool_id=contract.tool_id,
                arguments={"amount": 100},
            )

        count = database.connect().execute(
            "SELECT COUNT(*) FROM tool_requests WHERE user_id = ? AND tool_id = ?",
            (user_id, contract.tool_id),
        ).fetchone()[0]
        assert count == 0
    finally:
        database.shutdown()


def test_changed_read_only_contract_cannot_claim_execution(tmp_path):
    original_contract = read_only_echo_contract()
    database, user_id, original_gateway, requests = create_gateway(
        tmp_path,
        [original_contract],
    )
    try:
        proposal = original_gateway.propose(
            user_id,
            tool_id=original_contract.tool_id,
            arguments={"text": "contract-bound proposal"},
        )

        changed_contract = read_only_echo_contract(
            description="Changed contract after proposal",
        )
        changed_registry = ToolRegistry()
        changed_registry.register(changed_contract)
        changed_gateway = ToolExecutionGateway(changed_registry, database)

        with pytest.raises(
            PermissionError,
            match="Tool contract changed after proposal",
        ):
            changed_gateway.execute(
                {"id": proposal["id"], "user_id": user_id},
                user_id=user_id,
            )

        persisted = requests.get(user_id, proposal["id"])
        assert persisted["status"] == "approved"
        assert persisted["consumed_at"] is None
        assert execution_attempt_count(database, proposal["id"]) == 0
    finally:
        database.shutdown()
