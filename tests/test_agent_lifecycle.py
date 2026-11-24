import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.app.app_state import get_app_state
from backend.app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(client: TestClient, email: str) -> str:
    registered = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "safe-password-123",
            "display_name": "Lifecycle Owner",
        },
    )
    assert registered.status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "safe-password-123"},
    )
    assert login.status_code == 200
    return login.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_agent(client: TestClient, token: str) -> dict:
    response = client.post(
        "/api/v1/agents",
        headers=auth(token),
        json={"name": "Lifecycle test agent"},
    )
    assert response.status_code == 201
    return response.json()


def transition(
    client: TestClient,
    token: str,
    agent_id: str,
    status: str,
    reason: str = "",
):
    return client.patch(
        f"/api/v1/agents/{agent_id}/lifecycle",
        headers=auth(token),
        json={"status": status, "reason": reason},
    )


def test_agent_lifecycle_supports_explicit_activation_suspension_and_resume(
    client: TestClient,
) -> None:
    token = register_and_login(client, "agent-lifecycle-happy@example.com")
    agent = create_agent(client, token)

    activated = transition(client, token, agent["id"], "active", "Owner approved")
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"

    suspended = transition(client, token, agent["id"], "suspended", "Pause work")
    assert suspended.status_code == 200
    assert suspended.json()["status"] == "suspended"

    resumed = transition(client, token, agent["id"], "active", "Owner resumed")
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "active"

    events = client.get(
        f"/api/v1/agents/{agent['id']}/events",
        headers=auth(token),
    )
    assert events.status_code == 200
    assert [event["event_type"] for event in events.json()] == [
        "registered", "activated", "suspended", "resumed"
    ]
    assert events.json()[1]["details"]["reason"] == "Owner approved"
    assert all(event["actor_user_id"] == agent["user_id"] for event in events.json())


@pytest.mark.parametrize(
    ("initial_status", "requested_status"),
    [
        ("draft", "suspended"),
        ("active", "draft"),
        ("suspended", "suspended"),
        ("terminated", "active"),
    ],
)
def test_agent_lifecycle_rejects_invalid_or_repeated_transitions(
    client: TestClient,
    initial_status: str,
    requested_status: str,
) -> None:
    token = register_and_login(
        client,
        f"agent-invalid-{initial_status}-{requested_status}@example.com",
    )
    agent = create_agent(client, token)
    if initial_status in {"active", "terminated"}:
        assert transition(client, token, agent["id"], "active").status_code == 200
    if initial_status == "suspended":
        assert transition(client, token, agent["id"], "active").status_code == 200
        assert transition(client, token, agent["id"], "suspended").status_code == 200
    if initial_status == "terminated":
        assert transition(client, token, agent["id"], "terminated").status_code == 200

    response = transition(client, token, agent["id"], requested_status)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVALID_AGENT_TRANSITION"


def test_agent_termination_is_irreversible_and_audited(client: TestClient) -> None:
    token = register_and_login(client, "agent-termination@example.com")
    agent = create_agent(client, token)

    terminated = transition(client, token, agent["id"], "terminated", "Owner closed it")
    assert terminated.status_code == 200
    assert terminated.json()["status"] == "terminated"

    revival = transition(client, token, agent["id"], "active")
    assert revival.status_code == 409
    assert client.get(
        f"/api/v1/agents/{agent['id']}",
        headers=auth(token),
    ).json()["status"] == "terminated"

    events = client.get(
        f"/api/v1/agents/{agent['id']}/events",
        headers=auth(token),
    ).json()
    assert [event["event_type"] for event in events] == ["registered", "terminated"]
    assert events[-1]["details"] == {
        "from_status": "draft",
        "reason": "Owner closed it",
        "to_status": "terminated",
    }


def test_agent_lifecycle_requires_authentication_and_owner_scope(
    client: TestClient,
) -> None:
    owner = register_and_login(client, "agent-lifecycle-owner@example.com")
    other = register_and_login(client, "agent-lifecycle-other@example.com")
    agent = create_agent(client, owner)

    unauthenticated = client.patch(
        f"/api/v1/agents/{agent['id']}/lifecycle",
        json={"status": "active"},
    )
    assert unauthenticated.status_code == 401

    foreign = transition(client, other, agent["id"], "active")
    assert foreign.status_code == 404
    assert client.get(
        f"/api/v1/agents/{agent['id']}",
        headers=auth(owner),
    ).json()["status"] == "draft"


def test_database_rejects_status_update_without_matching_lifecycle_event(
    client: TestClient,
) -> None:
    token = register_and_login(client, "agent-lifecycle-db-guard@example.com")
    agent = create_agent(client, token)
    state = get_app_state()

    with pytest.raises(
        sqlite3.IntegrityError,
        match="requires a matching lifecycle event",
    ):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE agents SET status = 'active' WHERE id = ?",
                (agent["id"],),
            )


def test_database_rejects_lifecycle_event_with_wrong_transition(
    client: TestClient,
) -> None:
    token = register_and_login(client, "agent-lifecycle-event-guard@example.com")
    agent = create_agent(client, token)
    state = get_app_state()

    with pytest.raises(
        sqlite3.IntegrityError,
        match="transition mismatch",
    ):
        with state.database.transaction():
            state.database.connect().execute(
                """
                INSERT INTO agent_events (
                    id, user_id, agent_id, actor_user_id,
                    event_type, details_json, created_at
                ) VALUES (
                    'invalid-agent-event', ?, ?, ?,
                    'resumed', '{"from_status":"draft","to_status":"active"}',
                    '2026-11-24T00:00:00+00:00'
                )
                """,
                (agent["user_id"], agent["id"], agent["user_id"]),
            )


def test_account_erasure_removes_lifecycle_history(client: TestClient) -> None:
    token = register_and_login(client, "agent-lifecycle-erasure@example.com")
    agent = create_agent(client, token)
    assert transition(client, token, agent["id"], "active").status_code == 200
    state = get_app_state()
    owner = state.identity.resolve_token(token)

    state.identity.delete_user(owner["id"])

    assert state.database.connect().execute(
        "SELECT 1 FROM agents WHERE id = ?", (agent["id"],)
    ).fetchone() is None
    assert state.database.connect().execute(
        "SELECT 1 FROM agent_events WHERE agent_id = ?", (agent["id"],)
    ).fetchone() is None
