from datetime import datetime, timedelta, timezone

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



def test_passkey_options_endpoint_is_authenticated_and_request_scoped(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    owner_token = register_and_login(client, "passkey-options-owner@example.com")
    other_token = register_and_login(client, "passkey-options-other@example.com")
    owner_id = state.identity.resolve_token(owner_token)["id"]

    request = state.tool_requests.create(
        owner_id,
        tool_id="state-change-api-test",
        arguments={"value": "sensitive action"},
        status="pending",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )

    # Bypass the feature-availability guard so this test reaches the
    # request lookup and verifies cross-account resource isolation.
    monkeypatch.setattr(
        state.webauthn_service,
        "_require_enabled",
        lambda: None,
    )

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/passkey/options",
        headers=auth_header(other_token),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TOOL_REQUEST_NOT_FOUND"


def test_passkey_options_endpoint_returns_service_options_without_exposing_records(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-options-api@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    captured = {}

    def create_options(*, user_id: str, request_id: str) -> dict:
        captured["user_id"] = user_id
        captured["request_id"] = request_id
        return {
            "challenge_record_id": "challenge-record",
            "options": {"challenge": "browser-challenge"},
        }

    monkeypatch.setattr(
        state.webauthn_service,
        "create_tool_approval_options",
        create_options,
    )

    response = client.post(
        "/api/v1/tools/requests/request-123/passkey/options",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    assert response.json() == {
        "challenge_record_id": "challenge-record",
        "options": {"challenge": "browser-challenge"},
    }
    assert captured == {
        "user_id": user_id,
        "request_id": "request-123",
    }


def test_passkey_verify_endpoint_returns_only_approved_request_metadata(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-verify-api@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    captured = {}

    def verify_approval(
        *,
        user_id: str,
        request_id: str,
        challenge_record_id: str,
        credential_record_id: str,
        assertion: dict,
    ) -> dict:
        captured.update({
            "user_id": user_id,
            "request_id": request_id,
            "challenge_record_id": challenge_record_id,
            "credential_record_id": credential_record_id,
            "assertion": assertion,
        })
        return {
            "id": request_id,
            "tool_id": "state-change-api-test",
            "arguments": {"value": "approved"},
            "status": "approved",
            "expires_at": "2030-01-01T00:00:00+00:00",
            "consumed_at": None,
            "confirmation_id": "internal-confirmation",
            "contract_fingerprint": "a" * 64,
            "authorization_policy": "passkey",
        }

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_tool_approval",
        verify_approval,
    )

    response = client.post(
        "/api/v1/tools/requests/request-456/passkey/verify",
        headers=auth_header(token),
        json={
            "challenge_record_id": "challenge-456",
            "credential_record_id": "credential-456",
            "assertion": {"response": {"signature": "browser-data"}},
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": "request-456",
        "tool_id": "state-change-api-test",
        "arguments": {"value": "approved"},
        "status": "approved",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    assert captured == {
        "user_id": user_id,
        "request_id": "request-456",
        "challenge_record_id": "challenge-456",
        "credential_record_id": "credential-456",
        "assertion": {"response": {"signature": "browser-data"}},
    }


def test_passkey_verify_endpoint_hides_assertion_verification_details(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-verify-rejected@example.com")

    def reject_assertion(**kwargs):
        raise PermissionError("Detailed cryptographic failure")

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_tool_approval",
        reject_assertion,
    )

    response = client.post(
        "/api/v1/tools/requests/request-789/passkey/verify",
        headers=auth_header(token),
        json={
            "challenge_record_id": "challenge-789",
            "credential_record_id": "credential-789",
            "assertion": {},
        },
    )

    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "PASSKEY_APPROVAL_REJECTED"
    assert error["message"] == "Passkey approval could not be verified"
    assert "Detailed cryptographic failure" not in response.text
