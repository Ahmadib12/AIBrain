from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.app_state import get_app_state
from backend.app.main import app


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
            "display_name": "Reconciliation API Test",
        },
    )
    assert registered.status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "safe-password-123"},
    )
    assert login.status_code == 200
    return login.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_outcome_unknown_request(state, user_id: str) -> dict:
    request = state.tool_requests.create(
        user_id,
        tool_id="reconciliation-api-test",
        arguments={"operation": "check external operation"},
        status="approved",
        authorization_policy="read_only",
    )
    state.tool_requests.claim_for_execution(user_id, request["id"])
    cutoff = (
        datetime.now(timezone.utc) + timedelta(minutes=1)
    ).isoformat()
    assert state.tool_requests.recover_stale_execution_attempts(
        stale_before=cutoff
    ) == 1
    return state.tool_requests.get(user_id, request["id"])


def test_reconciliation_api_requires_authentication(client: TestClient) -> None:
    response = client.post(
        "/api/v1/tools/requests/request-id/reconcile",
        json={
            "outcome": "failed",
            "note": "Verified the operation did not occur.",
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_owner_can_reconcile_unknown_attempt_as_succeeded(client: TestClient) -> None:
    state = get_app_state()
    token = register_and_login(client, "reconcile-success@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = create_outcome_unknown_request(state, user_id)

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/reconcile",
        headers=auth_header(token),
        json={
            "outcome": "succeeded",
            "note": "Checked the external service and confirmed completion.",
            "result": {"verified": True},
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": request["id"],
        "tool_id": "reconciliation-api-test",
        "status": "completed",
        "result": {"verified": True},
    }
    persisted = state.tool_requests.get(user_id, request["id"])
    assert persisted["status"] == "completed"
    assert persisted["result"] == {"verified": True}
    attempt = state.tool_requests.get_execution_attempt(user_id, request["id"])
    assert attempt["status"] == "succeeded"

    audit_row = state.database.connect().execute(
        "SELECT audit_json FROM tool_requests WHERE id = ? AND user_id = ?",
        (request["id"], user_id),
    ).fetchone()
    import json
    audit = json.loads(audit_row["audit_json"])
    assert audit["execution_reconciliation"]["outcome"] == "succeeded"
    assert audit["execution_reconciliation"]["reconciled_by"] == user_id
    assert audit["execution_reconciliation"]["note"] == (
        "Checked the external service and confirmed completion."
    )


def test_owner_can_reconcile_unknown_attempt_as_failed(client: TestClient) -> None:
    state = get_app_state()
    token = register_and_login(client, "reconcile-failure@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = create_outcome_unknown_request(state, user_id)

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/reconcile",
        headers=auth_header(token),
        json={
            "outcome": "failed",
            "note": "Checked the external service; no operation was applied.",
            "error_code": "external_not_applied",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "failed"
    assert response.json()["result"] is None
    attempt = state.tool_requests.get_execution_attempt(user_id, request["id"])
    assert attempt["status"] == "failed"
    assert attempt["error_code"] == "external_not_applied"


def test_another_user_cannot_reconcile_or_discover_request(client: TestClient) -> None:
    state = get_app_state()
    owner_token = register_and_login(client, "reconcile-owner@example.com")
    other_token = register_and_login(client, "reconcile-other@example.com")
    owner_id = state.identity.resolve_token(owner_token)["id"]
    request = create_outcome_unknown_request(state, owner_id)

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/reconcile",
        headers=auth_header(other_token),
        json={
            "outcome": "failed",
            "note": "Attempted unauthorized reconciliation.",
        },
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TOOL_REQUEST_NOT_FOUND"
    assert state.tool_requests.get(owner_id, request["id"])["status"] == (
        "outcome_unknown"
    )


def test_reconciliation_rejects_requests_not_in_unknown_state(
    client: TestClient,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "reconcile-not-unknown@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = state.tool_requests.create(
        user_id,
        tool_id="reconciliation-api-test",
        arguments={"operation": "not yet executed"},
        status="approved",
        authorization_policy="read_only",
    )

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/reconcile",
        headers=auth_header(token),
        json={
            "outcome": "failed",
            "note": "This request was never executed.",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "RECONCILIATION_NOT_AVAILABLE"
    assert state.tool_requests.get(user_id, request["id"])["status"] == (
        "approved"
    )


def test_duplicate_reconciliation_is_rejected(client: TestClient) -> None:
    state = get_app_state()
    token = register_and_login(client, "reconcile-duplicate@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = create_outcome_unknown_request(state, user_id)
    payload = {
        "outcome": "failed",
        "note": "Confirmed the external operation was not applied.",
    }
    url = f"/api/v1/tools/requests/{request['id']}/reconcile"

    first = client.post(url, headers=auth_header(token), json=payload)
    second = client.post(url, headers=auth_header(token), json=payload)

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "RECONCILIATION_NOT_AVAILABLE"


@pytest.mark.parametrize(
    "payload",
    [
        {"outcome": "unknown", "note": "Invalid outcome."},
        {"outcome": "succeeded", "note": "Missing success result."},
        {
            "outcome": "failed",
            "note": "Failure must not include a result.",
            "result": {"applied": True},
        },
        {"outcome": "failed", "note": "   "},
        {
            "outcome": "failed",
            "note": "Invalid error code.",
            "error_code": "invalid-code",
        },
    ],
)
def test_invalid_reconciliation_payload_is_rejected(
    client: TestClient,
    payload: dict,
) -> None:
    state = get_app_state()
    token = register_and_login(
        client,
        f"reconcile-invalid-{abs(hash(str(payload)))}@example.com",
    )
    user_id = state.identity.resolve_token(token)["id"]
    request = create_outcome_unknown_request(state, user_id)

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/reconcile",
        headers=auth_header(token),
        json=payload,
    )

    assert response.status_code in (400, 422)
    assert state.tool_requests.get(user_id, request["id"])["status"] == (
        "outcome_unknown"
    )


def test_reconciliation_rejects_unexpected_request_fields(client: TestClient) -> None:
    state = get_app_state()
    token = register_and_login(client, "reconcile-extra-field@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = create_outcome_unknown_request(state, user_id)

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/reconcile",
        headers=auth_header(token),
        json={
            "outcome": "failed",
            "note": "Checked the remote operation.",
            "user_id": "attacker-controlled-user",
        },
    )

    assert response.status_code == 422
    assert state.tool_requests.get(user_id, request["id"])["status"] == (
        "outcome_unknown"
    )
