import pytest

from backend.app.tools import ToolContract, ToolRegistry, ToolRisk
from backend.app.tools.contracts import contract_fingerprint


def make_contract(**overrides):
    values = {
        "tool_id": "example",
        "name": "Example tool",
        "description": "A test tool",
        "risk": ToolRisk.READ_ONLY,
        "input_schema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
        },
        "output_schema": {"type": "object"},
    }
    values.update(overrides)
    return ToolContract(**values)


def test_contract_version_defaults_to_one():
    contract = make_contract()
    assert contract.version == 1


@pytest.mark.parametrize("version", [0, -1, True, 1.5, "1"])
def test_contract_rejects_invalid_versions(version):
    with pytest.raises(ValueError, match="positive integer"):
        make_contract(version=version)


def test_identical_contracts_have_identical_fingerprints():
    first = make_contract()
    second = make_contract()

    assert contract_fingerprint(first) == contract_fingerprint(second)


@pytest.mark.parametrize(
    "change",
    [
        {"tool_id": "different"},
        {"name": "Different name"},
        {"description": "Different description"},
        {"risk": ToolRisk.STATE_CHANGE},
        {"version": 2},
        {
            "input_schema": {
                "type": "object",
                "properties": {"text": {"type": "string", "maxLength": 20}},
            }
        },
        {"output_schema": {"type": "string"}},
    ],
)
def test_security_relevant_contract_changes_change_fingerprint(change):
    original = make_contract()
    modified = make_contract(**change)

    assert contract_fingerprint(original) != contract_fingerprint(modified)


def test_schema_key_order_does_not_change_fingerprint():
    first = make_contract(
        input_schema={
            "type": "object",
            "properties": {
                "first": {"type": "string"},
                "second": {"type": "integer"},
            },
        }
    )
    second = make_contract(
        input_schema={
            "properties": {
                "second": {"type": "integer"},
                "first": {"type": "string"},
            },
            "type": "object",
        }
    )

    assert contract_fingerprint(first) == contract_fingerprint(second)


def test_gateway_persists_contract_fingerprint(tmp_path):
    from backend.app.persistence.database import Database
    from backend.app.persistence.identity import IdentityRepository
    from backend.app.tools import ToolExecutionGateway, ToolRegistry

    database = Database(f"sqlite:///{tmp_path / 'fingerprint.db'}")
    try:
        identity = IdentityRepository(database, session_ttl_seconds=86400)
        user = identity.register(
            email="fingerprint@example.com",
            password="StrongTestPassword123!",
            display_name="Fingerprint Test",
        )

        contract = make_contract()
        registry = ToolRegistry()
        registry.register(contract)
        gateway = ToolExecutionGateway(registry, database)

        proposal = gateway.propose(
            user["id"],
            tool_id=contract.tool_id,
            arguments={"text": "hello"},
        )

        persisted = gateway._tool_requests.get(user["id"], proposal["id"])
        assert persisted["contract_fingerprint"] == contract_fingerprint(contract)
    finally:
        database.shutdown()


def test_gateway_rejects_execution_after_contract_changes(tmp_path):
    from backend.app.persistence.database import Database
    from backend.app.persistence.identity import IdentityRepository
    from backend.app.tools import ToolExecutionGateway, ToolRegistry

    database = Database(f"sqlite:///{tmp_path / 'contract-drift.db'}")
    try:
        identity = IdentityRepository(database, session_ttl_seconds=86400)
        user = identity.register(
            email="contract-drift@example.com",
            password="StrongTestPassword123!",
            display_name="Contract Drift Test",
        )

        original = make_contract()
        registry = ToolRegistry()
        registry.register(original)
        gateway = ToolExecutionGateway(registry, database)

        proposal = gateway.propose(
            user["id"],
            tool_id=original.tool_id,
            arguments={"text": "hello"},
        )

        changed_registry = ToolRegistry()
        changed_registry.register(
            make_contract(description="Changed security contract")
        )
        changed_gateway = ToolExecutionGateway(changed_registry, database)

        with pytest.raises(PermissionError, match="contract changed"):
            changed_gateway.execute(proposal, user_id=user["id"])

        persisted = changed_gateway._tool_requests.get(user["id"], proposal["id"])
        assert persisted["status"] == "approved"
        assert persisted["consumed_at"] is None
    finally:
        database.shutdown()


def test_gateway_rejects_legacy_request_without_contract_fingerprint(tmp_path):
    from backend.app.persistence.database import Database
    from backend.app.persistence.identity import IdentityRepository
    from backend.app.tools import ToolExecutionGateway, ToolRegistry

    database = Database(f"sqlite:///{tmp_path / 'legacy-fingerprint.db'}")
    try:
        identity = IdentityRepository(database, session_ttl_seconds=86400)
        user = identity.register(
            email="legacy-fingerprint@example.com",
            password="StrongTestPassword123!",
            display_name="Legacy Fingerprint Test",
        )

        contract = make_contract()
        registry = ToolRegistry()
        registry.register(contract)
        gateway = ToolExecutionGateway(registry, database)

        legacy = gateway._tool_requests.create(
            user["id"],
            tool_id=contract.tool_id,
            arguments={"text": "hello"},
            status="approved",
        )
        proposal = {
            "id": legacy["id"],
            "user_id": user["id"],
        }

        with pytest.raises(PermissionError, match="contract changed"):
            gateway.execute(proposal, user_id=user["id"])

        persisted = gateway._tool_requests.get(user["id"], legacy["id"])
        assert persisted["consumed_at"] is None
    finally:
        database.shutdown()


def test_registry_isolates_contract_from_original_mutations():
    original = make_contract()
    registry = ToolRegistry()

    registry.register(original)
    original_fingerprint = contract_fingerprint(registry.get("example"))

    original.input_schema["properties"]["text"]["maxLength"] = 1
    original.output_schema["type"] = "string"

    registered = registry.get("example")
    assert registered.description == "A test tool"
    assert "maxLength" not in registered.input_schema["properties"]["text"]
    assert registered.output_schema["type"] == "object"
    assert contract_fingerprint(registered) == original_fingerprint


def test_registry_get_and_list_return_defensive_copies():
    registry = ToolRegistry()
    registry.register(make_contract())

    retrieved = registry.get("example")
    listed = registry.list()[0]

    retrieved.input_schema["properties"]["text"]["type"] = "integer"
    listed.output_schema["type"] = "string"

    stored = registry.get("example")
    assert stored.input_schema["properties"]["text"]["type"] == "string"
    assert stored.output_schema["type"] == "object"
