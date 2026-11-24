from datetime import datetime, timedelta, timezone

import json

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
            "display_name": "Operator History Test",
        },
    )
    assert registered.status_code == 200
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "safe-password-123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_reconciled_request(state, user_id: str) -> dict:
    request = state.tool_requests.create(
        user_id,
        tool_id="operator-history-test",
        arguments={"private_argument": "must-not-be-returned"},
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
    state.tool_requests.reconcile_execution_attempt(
        user_id,
        request["id"],
        outcome="failed",
        note="Verified the external operation was not applied.",
        error_code="confirmed_not_applied",
    )
    return request


def test_operator_history_requires_authenticated_allowlisted_account(
    client: TestClient,
    monkeypatch,
) -> None:
    url = "/api/v1/tools/operator/requests/unknown-request/history"
    unauthenticated = client.get(url, params={"reason": "Security incident review"})
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["error"]["code"] == "UNAUTHORIZED"

    monkeypatch.setenv("AIBRAIN_SECURITY_OPERATOR_EMAILS", "security@example.com")
    token = register_and_login(client, "ordinary-user@example.com")
    forbidden = client.get(
        url,
        headers=auth_header(token),
        params={"reason": "Security incident review"},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"] == "SECURITY_OPERATOR_FORBIDDEN"


def test_operator_history_requires_bounded_investigation_reason(
    client: TestClient,
    monkeypatch,
) -> None:
    email = "history-operator-reason@example.com"
    monkeypatch.setenv("AIBRAIN_SECURITY_OPERATOR_EMAILS", email)
    token = register_and_login(client, email)

    response = client.get(
        "/api/v1/tools/operator/requests/unknown-request/history",
        headers=auth_header(token),
    )
    assert response.status_code == 422

    whitespace_reason = client.get(
        "/api/v1/tools/operator/requests/unknown-request/history",
        headers=auth_header(token),
        params={"reason": "        "},
    )
    assert whitespace_reason.status_code == 400


def test_security_operator_history_read_is_redacted_and_audited(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    operator_email = "history-investigator@example.com"
    monkeypatch.setenv("AIBRAIN_SECURITY_OPERATOR_EMAILS", operator_email)
    operator_token = register_and_login(client, operator_email)
    operator_id = state.identity.resolve_token(operator_token)["id"]

    owner_token = register_and_login(client, "history-subject@example.com")
    owner_id = state.identity.resolve_token(owner_token)["id"]
    request = create_reconciled_request(state, owner_id)

    response = client.get(
        f"/api/v1/tools/operator/requests/{request['id']}/history",
        headers=auth_header(operator_token),
        params={
            "reason": "Investigating reported execution outcome",
            "limit": 10,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["request"] == {
        "request_id": request["id"],
        "owner_user_id": owner_id,
        "tool_id": "operator-history-test",
        "status": "failed",
        "created_at": body["request"]["created_at"],
        "consumed_at": body["request"]["consumed_at"],
        "execution_attempt": {
            "status": "failed",
            "claimed_at": body["request"]["execution_attempt"]["claimed_at"],
            "finished_at": body["request"]["execution_attempt"]["finished_at"],
            "error_code": "confirmed_not_applied",
        },
    }
    assert body["request"]["execution_attempt"]["claimed_at"]
    assert body["request"]["execution_attempt"]["finished_at"]
    assert "arguments" not in body["request"]
    assert "result" not in body["request"]

    assert len(body["items"]) == 1
    event = body["items"][0]
    assert event["record_type"] == "execution_reconciliation"
    assert event["details"] == {
        "outcome": "failed",
        "error_code": "confirmed_not_applied",
        "note": "Verified the external operation was not applied.",
        "reconciled_by": owner_id,
    }
    assert body["pagination"] == {
        "limit": 10,
        "offset": 0,
        "has_more": False,
        "next_offset": None,
    }
    assert "private_argument" not in json.dumps(body)

    audit = state.database.connect().execute(
        """
        SELECT actor_user_id, actor_email, action, target_type,
               target_id, details_json
        FROM security_operator_audit_events
        WHERE actor_user_id = ?
          AND action = 'tool_execution_history.view'
          AND target_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (operator_id, request["id"]),
    ).fetchone()
    assert audit is not None
    assert audit["actor_user_id"] == operator_id
    assert audit["actor_email"] == operator_email
    assert audit["target_type"] == "tool_request"
    assert json.loads(audit["details_json"]) == {
        "reason": "Investigating reported execution outcome",
        "request_owner_id": owner_id,
        "tool_id": "operator-history-test",
        "limit": 10,
        "offset": 0,
    }


def test_operator_history_does_not_audit_unknown_request(
    client: TestClient,
    monkeypatch,
) -> None:
    email = "history-operator-not-found@example.com"
    monkeypatch.setenv("AIBRAIN_SECURITY_OPERATOR_EMAILS", email)
    token = register_and_login(client, email)
    state = get_app_state()
    operator_id = state.identity.resolve_token(token)["id"]

    response = client.get(
        "/api/v1/tools/operator/requests/not-a-real-request/history",
        headers=auth_header(token),
        params={"reason": "Investigating a reported request"},
    )

    assert response.status_code == 404
    audit = state.database.connect().execute(
        """
        SELECT 1 FROM security_operator_audit_events
        WHERE actor_user_id = ?
          AND action = 'tool_execution_history.view'
          AND target_id = 'not-a-real-request'
        """,
        (operator_id,),
    ).fetchone()
    assert audit is None


def test_operator_history_rejects_invalid_pagination(
    client: TestClient,
    monkeypatch,
) -> None:
    email = "history-operator-pagination@example.com"
    monkeypatch.setenv("AIBRAIN_SECURITY_OPERATOR_EMAILS", email)
    token = register_and_login(client, email)
    headers = auth_header(token)
    url = "/api/v1/tools/operator/requests/not-a-real-request/history"
    for params in (
        {"reason": "Investigating a report", "limit": 0},
        {"reason": "Investigating a report", "limit": 51},
        {"reason": "Investigating a report", "offset": -1},
    ):
        response = client.get(url, headers=headers, params=params)
        assert response.status_code == 422
