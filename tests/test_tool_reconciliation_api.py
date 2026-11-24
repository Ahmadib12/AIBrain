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

    history = state.tool_requests.get_execution_history(user_id, request["id"])
    reconciliation_events = [
        event for event in history
        if event["record_type"] == "execution_reconciliation"
    ]
    assert len(reconciliation_events) == 1
    assert reconciliation_events[0]["details"]["outcome"] == "succeeded"
    assert reconciliation_events[0]["details"]["reconciled_by"] == user_id
    assert reconciliation_events[0]["details"]["note"] == (
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


def test_owner_can_inspect_unknown_execution_and_attempt_state(
    client: TestClient,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "reconcile-inspect@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = create_outcome_unknown_request(state, user_id)

    response = client.get(
        f"/api/v1/tools/requests/{request['id']}",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == request["id"]
    assert body["status"] == "outcome_unknown"
    assert body["execution_attempt"]["status"] == "outcome_unknown"
    assert body["execution_attempt"]["claimed_at"]


def test_another_user_cannot_inspect_tool_request(client: TestClient) -> None:
    state = get_app_state()
    owner_token = register_and_login(client, "reconcile-inspect-owner@example.com")
    other_token = register_and_login(client, "reconcile-inspect-other@example.com")
    owner_id = state.identity.resolve_token(owner_token)["id"]
    request = create_outcome_unknown_request(state, owner_id)

    response = client.get(
        f"/api/v1/tools/requests/{request['id']}",
        headers=auth_header(other_token),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TOOL_REQUEST_NOT_FOUND"



def test_execution_history_api_requires_authentication(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/tools/requests/request-id/history",
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_owner_can_page_redacted_execution_history(
    client: TestClient,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "history-page@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = create_outcome_unknown_request(state, user_id)

    connection = state.database.connect()
    # These synthetic rows exercise the read projection and page boundary;
    # production insert validation remains covered by dispatcher tests.
    connection.execute("DROP TRIGGER validate_tool_dispatch_audit_event")
    connection.executemany(
        """
        INSERT INTO tool_dispatch_audit_events (
            id, user_id, request_id, event_type, action_digest,
            details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                "history-started",
                user_id,
                request["id"],
                "dispatch_started",
                "a" * 64,
                (
                    '{"attempt_id":"attempt-1","adapter_id":"adapter-a",'
                    '"adapter_version":"1.0","provider_id":"provider-a",'
                    '"provider_scope":"scope-a","runner_key_id":"private-key",'
                    '"evidence_package_id":"private-package",'
                    '"tool_contract_fingerprint":"private-fingerprint"}'
                ),
                "2026-11-24T10:00:00+00:00",
            ),
            (
                "history-failed",
                user_id,
                request["id"],
                "dispatch_failed",
                "a" * 64,
                (
                    '{"error_code":"provider_timeout",'
                    '"evidence_reference":"private-provider-reference"}'
                ),
                "2026-11-24T10:00:01+00:00",
            ),
        ],
    )
    connection.commit()

    url = f"/api/v1/tools/requests/{request['id']}/history"
    first = client.get(
        url,
        headers=auth_header(token),
        params={"limit": 1},
    )
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["pagination"] == {
        "limit": 1,
        "offset": 0,
        "has_more": True,
        "next_offset": 1,
    }
    assert len(first_body["items"]) == 1
    assert first_body["items"][0]["event_type"] == "dispatch_started"
    assert first_body["items"][0]["details"] == {
        "attempt_id": "attempt-1",
        "adapter_id": "adapter-a",
        "adapter_version": "1.0",
        "provider_id": "provider-a",
        "provider_scope": "scope-a",
    }

    second = client.get(
        url,
        headers=auth_header(token),
        params={"limit": 1, "offset": 1},
    )
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["pagination"]["has_more"] is False
    assert second_body["pagination"]["next_offset"] is None
    assert second_body["items"][0]["event_type"] == "dispatch_failed"
    assert second_body["items"][0]["details"] == {
        "error_code": "provider_timeout",
    }


def test_another_user_cannot_read_execution_history(
    client: TestClient,
) -> None:
    state = get_app_state()
    owner_token = register_and_login(client, "history-owner@example.com")
    other_token = register_and_login(client, "history-other@example.com")
    owner_id = state.identity.resolve_token(owner_token)["id"]
    request = create_outcome_unknown_request(state, owner_id)

    response = client.get(
        f"/api/v1/tools/requests/{request['id']}/history",
        headers=auth_header(other_token),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TOOL_REQUEST_NOT_FOUND"


def test_execution_history_api_bounds_pagination(
    client: TestClient,
) -> None:
    token = register_and_login(client, "history-bounds@example.com")
    url = "/api/v1/tools/requests/request-id/history"
    for params in ({"limit": 0}, {"limit": 101}, {"offset": -1}):
        response = client.get(
            url,
            headers=auth_header(token),
            params=params,
        )
        assert response.status_code == 422
