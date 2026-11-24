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
            "display_name": "Agent Test Owner",
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


def test_agent_registration_creates_owner_scoped_draft_and_event(
    client: TestClient,
) -> None:
    token = register_and_login(client, "agent-owner-one@example.com")
    response = client.post(
        "/api/v1/agents",
        headers=auth(token),
        json={
            "name": "Research assistant",
            "description": "Collects and organizes research notes",
            "metadata": {"purpose": "research", "version": 1},
        },
    )
    assert response.status_code == 201
    agent = response.json()
    assert agent["id"]
    assert agent["name"] == "Research assistant"
    assert agent["description"] == "Collects and organizes research notes"
    assert agent["metadata"] == {"purpose": "research", "version": 1}
    assert agent["status"] == "draft"
    assert agent["user_id"]

    listed = client.get("/api/v1/agents", headers=auth(token))
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [agent["id"]]

    events = client.get(
        f"/api/v1/agents/{agent['id']}/events",
        headers=auth(token),
    )
    assert events.status_code == 200
    assert len(events.json()) == 1
    assert events.json()[0]["event_type"] == "registered"
    assert events.json()[0]["actor_user_id"] == agent["user_id"]
    assert events.json()[0]["details"] == {"initial_status": "draft"}


def test_agent_identity_is_not_shared_between_accounts(client: TestClient) -> None:
    owner_token = register_and_login(client, "agent-owner-two@example.com")
    other_token = register_and_login(client, "agent-other-owner@example.com")
    created = client.post(
        "/api/v1/agents",
        headers=auth(owner_token),
        json={"name": "Private agent"},
    )
    agent_id = created.json()["id"]

    assert client.get("/api/v1/agents", headers=auth(other_token)).json() == []
    assert client.get(
        f"/api/v1/agents/{agent_id}",
        headers=auth(other_token),
    ).status_code == 404
    assert client.get(
        f"/api/v1/agents/{agent_id}/events",
        headers=auth(other_token),
    ).status_code == 404


def test_agent_registration_requires_authentication(client: TestClient) -> None:
    response = client.post(
        "/api/v1/agents",
        json={"name": "Unauthenticated agent"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "   "},
        {"name": "x" * 101},
        {"name": "Valid", "metadata": []},
        {"name": "Valid", "metadata": {"api_key": "should-not-be-stored"}},
        {"name": "Valid", "metadata": {"note": "password=unsafe"}},
    ],
)
def test_agent_registration_rejects_invalid_or_sensitive_metadata(
    client: TestClient,
    payload: dict,
) -> None:
    token = register_and_login(client, "agent-invalid-payload@example.com")
    response = client.post(
        "/api/v1/agents",
        headers=auth(token),
        json=payload,
    )
    assert response.status_code in (400, 422)
    assert client.get("/api/v1/agents", headers=auth(token)).json() == []


def test_agent_event_ledger_is_immutable_outside_account_erasure(
    client: TestClient,
) -> None:
    token = register_and_login(client, "agent-ledger@example.com")
    created = client.post(
        "/api/v1/agents",
        headers=auth(token),
        json={"name": "Ledger agent"},
    )
    agent_id = created.json()["id"]
    state = get_app_state()
    owner = state.identity.resolve_token(token)
    event = state.database.connect().execute(
        "SELECT id FROM agent_events WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    assert event is not None

    with pytest.raises(sqlite3.IntegrityError, match="agent events are immutable"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE agent_events SET event_type = 'registered' WHERE id = ?",
                (event["id"],),
            )

    with pytest.raises(sqlite3.IntegrityError, match="may only be deleted"):
        with state.database.transaction():
            state.database.connect().execute(
                "DELETE FROM agent_events WHERE id = ?",
                (event["id"],),
            )

    with pytest.raises(sqlite3.IntegrityError, match="may only be deleted"):
        with state.database.transaction():
            state.database.connect().execute(
                "DELETE FROM agents WHERE id = ?",
                (agent_id,),
            )

    assert state.identity.get_user(owner["id"])["id"] == owner["id"]


def test_agent_records_are_removed_during_owner_account_erasure(
    client: TestClient,
) -> None:
    token = register_and_login(client, "agent-account-erasure@example.com")
    created = client.post(
        "/api/v1/agents",
        headers=auth(token),
        json={"name": "Erasure agent"},
    )
    assert created.status_code == 201
    agent_id = created.json()["id"]
    state = get_app_state()
    owner = state.identity.resolve_token(token)

    state.identity.delete_user(owner["id"])

    assert state.database.connect().execute(
        "SELECT 1 FROM agents WHERE id = ?",
        (agent_id,),
    ).fetchone() is None
    assert state.database.connect().execute(
        "SELECT 1 FROM agent_events WHERE agent_id = ?",
        (agent_id,),
    ).fetchone() is None
    with pytest.raises(LookupError):
        state.identity.resolve_token(token)
