import pytest
from fastapi.testclient import TestClient

from backend.app.app_state import get_app_state
from backend.app.main import app
from backend.app.api.v1.tools import tool_registry
from backend.app.tools import ToolContract, ToolRisk


@pytest.fixture
def client():
    get_app_state()
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(client: TestClient, email: str) -> str:
    registered = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "safe-password-123",
            "display_name": "Tool API Test",
        },
    )
    assert registered.status_code == 200

    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "safe-password-123",
        },
    )
    assert login.status_code == 200
    return login.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def state_change_contract() -> ToolContract:
    return ToolContract(
        tool_id="state-change-api-test",
        name="State change API test",
        description="Test-only state-changing tool",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={
            "type": "object",
            "properties": {
                "value": {"type": "string", "maxLength": 100},
            },
            "required": ["value"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


def test_state_change_proposal_cannot_be_confirmed_without_human_authorization(
    client: TestClient,
    monkeypatch,
) -> None:
    contract = state_change_contract()
    monkeypatch.setitem(tool_registry._tools, contract.tool_id, contract)

    token = register_and_login(client, "tool-proposal-api@example.com")
    headers = auth_header(token)

    proposed = client.post(
        "/api/v1/tools/requests",
        headers=headers,
        json={
            "tool_id": contract.tool_id,
            "arguments": {"value": "review this action"},
        },
    )

    assert proposed.status_code == 200
    proposal = proposed.json()
    assert proposal["tool_id"] == contract.tool_id
    assert proposal["arguments"] == {"value": "review this action"}
    assert proposal["status"] == "pending"

    confirmed = client.post(
        f"/api/v1/tools/requests/{proposal['id']}/confirm",
        headers=headers,
    )

    assert confirmed.status_code == 409
    assert (
        confirmed.json()["error"]["code"]
        == "CONFIRMATION_NOT_AVAILABLE"
    )

    state = get_app_state()
    persisted = state.tool_requests.get(
        state.identity.resolve_token(token)["id"],
        proposal["id"],
    )
    assert persisted["status"] == "pending"
    assert persisted["consumed_at"] is None
    assert persisted["result"] is None


def test_immediate_execution_rejects_state_change_before_persistence(
    client: TestClient,
    monkeypatch,
) -> None:
    contract = state_change_contract()
    monkeypatch.setitem(tool_registry._tools, contract.tool_id, contract)

    token = register_and_login(client, "tool-execute-blocked@example.com")
    user_id = get_app_state().identity.resolve_token(token)["id"]

    response = client.post(
        "/api/v1/tools/execute",
        headers=auth_header(token),
        json={
            "tool_id": contract.tool_id,
            "arguments": {"value": "must not be persisted"},
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CONFIRMATION_REQUIRED"

    state = get_app_state()
    count = state.database.connect().execute(
        "SELECT COUNT(*) FROM tool_requests "
        "WHERE user_id = ? AND tool_id = ?",
        (user_id, contract.tool_id),
    ).fetchone()[0]
    assert count == 0
