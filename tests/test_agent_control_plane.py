from datetime import datetime, timedelta, timezone
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from backend.app.app_state import get_app_state
from backend.app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def owner_token(client: TestClient, email: str) -> str:
    client.post("/api/v1/auth/register", json={
        "email": email, "password": "safe-password-123",
        "display_name": "Agent Control Owner",
    })
    response = client.post("/api/v1/auth/login", json={
        "email": email, "password": "safe-password-123",
    })
    assert response.status_code == 200
    return response.json()["access_token"]


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_active_agent(client: TestClient, token: str, name: str) -> dict:
    created = client.post("/api/v1/agents", headers=headers(token),
                          json={"name": name})
    assert created.status_code == 201
    agent = created.json()
    activated = client.patch(
        f"/api/v1/agents/{agent['id']}/lifecycle",
        headers=headers(token), json={"status": "active"},
    )
    assert activated.status_code == 200
    return agent


def expiry(seconds: int = 3600) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def test_capability_grants_are_allowlisted_owner_scoped_and_revocable(client):
    owner = owner_token(client, "control-grant-owner@example.com")
    other = owner_token(client, "control-grant-other@example.com")
    agent = create_active_agent(client, owner, "Grant target")

    invalid = client.post(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=headers(owner), json={"capability": "*"},
    )
    assert invalid.status_code == 400

    grant_response = client.post(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=headers(owner),
        json={"capability": "notes.read", "expires_at": expiry()},
    )
    assert grant_response.status_code == 201
    grant = grant_response.json()
    assert grant["capability"] == "notes.read"
    assert grant["revoked"] == 0

    foreign = client.get(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=headers(other),
    )
    assert foreign.status_code == 404

    revoked = client.request(
        "DELETE",
        f"/api/v1/agents/{agent['id']}/capabilities/{grant['id']}",
        headers=headers(owner), json={"reason": "Owner withdrew access"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] == 1
    repeated = client.request(
        "DELETE",
        f"/api/v1/agents/{agent['id']}/capabilities/{grant['id']}",
        headers=headers(owner), json={},
    )
    assert repeated.status_code == 409


def test_capability_grants_require_active_agent_and_future_expiry(client):
    token = owner_token(client, "control-grant-state@example.com")
    created = client.post("/api/v1/agents", headers=headers(token),
                          json={"name": "Draft agent"}).json()
    draft_grant = client.post(
        f"/api/v1/agents/{created['id']}/capabilities",
        headers=headers(token), json={"capability": "web.search"},
    )
    assert draft_grant.status_code == 400

    active = create_active_agent(client, token, "Active agent")
    expired = client.post(
        f"/api/v1/agents/{active['id']}/capabilities",
        headers=headers(token),
        json={"capability": "web.search", "expires_at": "2000-01-01T00:00:00+00:00"},
    )
    assert expired.status_code == 400


def test_task_ceiling_must_be_subset_of_current_grants(client):
    token = owner_token(client, "control-task-ceiling@example.com")
    agent = create_active_agent(client, token, "Task agent")
    deadline = expiry()
    denied = client.post(
        f"/api/v1/agents/{agent['id']}/tasks",
        headers=headers(token),
        json={"title": "Unapproved", "goal": "Do work",
              "capability_ceiling": ["files.read"], "expires_at": deadline},
    )
    assert denied.status_code == 400

    grant = client.post(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=headers(token), json={"capability": "research.read"},
    )
    assert grant.status_code == 201
    accepted = client.post(
        f"/api/v1/agents/{agent['id']}/tasks",
        headers=headers(token),
        json={"title": "Research task", "goal": "Summarize a topic",
              "context": {"source": "owner"}, "capability_ceiling": ["research.read"],
              "expires_at": deadline},
    )
    assert accepted.status_code == 201
    assert accepted.json()["status"] == "assigned"
    assert accepted.json()["capability_ceiling"] == ["research.read"]


def test_revoked_grant_cannot_be_used_for_new_task(client):
    token = owner_token(client, "control-task-revoked@example.com")
    agent = create_active_agent(client, token, "Revocation agent")
    grant = client.post(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=headers(token), json={"capability": "calendar.read"},
    ).json()
    revoked = client.request(
        "DELETE", f"/api/v1/agents/{agent['id']}/capabilities/{grant['id']}",
        headers=headers(token), json={},
    )
    assert revoked.status_code == 200
    denied = client.post(
        f"/api/v1/agents/{agent['id']}/tasks",
        headers=headers(token),
        json={"title": "Calendar task", "goal": "Read calendar",
              "capability_ceiling": ["calendar.read"], "expires_at": expiry()},
    )
    assert denied.status_code == 400


def test_task_lifecycle_and_owner_isolation(client):
    owner = owner_token(client, "control-task-owner@example.com")
    other = owner_token(client, "control-task-other@example.com")
    agent = create_active_agent(client, owner, "Task lifecycle agent")
    task = client.post(
        f"/api/v1/agents/{agent['id']}/tasks",
        headers=headers(owner),
        json={"title": "Track task", "goal": "No execution",
              "expires_at": expiry()},
    ).json()
    assert task["status"] == "assigned"

    foreign = client.get(f"/api/v1/agent-tasks/{task['id']}",
                         headers=headers(other))
    assert foreign.status_code == 404
    started = client.patch(
        f"/api/v1/agent-tasks/{task['id']}/lifecycle",
        headers=headers(owner), json={"status": "in_progress"},
    )
    assert started.status_code == 200
    completed = client.patch(
        f"/api/v1/agent-tasks/{task['id']}/lifecycle",
        headers=headers(owner), json={"status": "completed", "reason": "Owner confirmed"},
    )
    assert completed.status_code == 200
    repeated = client.patch(
        f"/api/v1/agent-tasks/{task['id']}/lifecycle",
        headers=headers(owner), json={"status": "in_progress"},
    )
    assert repeated.status_code == 409
    events = client.get(
        f"/api/v1/agent-tasks/{task['id']}/events", headers=headers(owner)
    )
    assert events.status_code == 200
    assert [event["event_type"] for event in events.json()] == [
        "assigned", "in_progress", "completed"
    ]


def test_expiry_reconciliation_marks_only_stale_open_tasks(client):
    token = owner_token(client, "control-task-expiry@example.com")
    agent = create_active_agent(client, token, "Expiry agent")
    task = client.post(
        f"/api/v1/agents/{agent['id']}/tasks", headers=headers(token),
        json={"title": "Will expire", "expires_at": expiry(seconds=1)},
    ).json()
    state = get_app_state()
    time.sleep(1.1)
    result = client.post("/api/v1/agent-tasks/reconcile-expired",
                         headers=headers(token))
    assert result.status_code == 200
    assert result.json()["expired"] == 1
    assert state.agent_control.get_task(
        state.identity.resolve_token(token)["id"], task["id"]
    )["status"] == "expired"


def test_same_owner_active_agent_messages_are_bounded_and_immutable(client):
    token = owner_token(client, "control-message-owner@example.com")
    sender = create_active_agent(client, token, "Message sender")
    recipient = create_active_agent(client, token, "Message recipient")
    sent = client.post(
        f"/api/v1/agents/{sender['id']}/messages",
        headers=headers(token),
        json={"recipient_agent_id": recipient["id"],
              "payload": {"kind": "note", "text": "Please review this"}},
    )
    assert sent.status_code == 201
    message = sent.json()
    assert message["payload"]["text"] == "Please review this"
    listed = client.get(
        f"/api/v1/agents/{recipient['id']}/messages", headers=headers(token)
    )
    assert [item["id"] for item in listed.json()] == [message["id"]]

    secret = client.post(
        f"/api/v1/agents/{sender['id']}/messages",
        headers=headers(token),
        json={"recipient_agent_id": recipient["id"],
              "payload": {"api_key": "must-not-be-stored"}},
    )
    assert secret.status_code == 400

    state = get_app_state()
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE agent_messages SET payload_json='{}' WHERE id=?",
                (message["id"],),
            )


def test_messages_cannot_cross_owner_boundaries(client):
    owner = owner_token(client, "control-message-a@example.com")
    other = owner_token(client, "control-message-b@example.com")
    sender = create_active_agent(client, owner, "Private sender")
    recipient = create_active_agent(client, other, "Foreign recipient")
    response = client.post(
        f"/api/v1/agents/{sender['id']}/messages",
        headers=headers(owner),
        json={"recipient_agent_id": recipient["id"], "payload": {"text": "No"}},
    )
    assert response.status_code == 404


def test_control_records_are_removed_during_account_erasure(client):
    token = owner_token(client, "control-erasure@example.com")
    first = create_active_agent(client, token, "Erasure one")
    second = create_active_agent(client, token, "Erasure two")
    grant = client.post(
        f"/api/v1/agents/{first['id']}/capabilities",
        headers=headers(token), json={"capability": "notes.read"},
    ).json()
    client.request(
        "DELETE", f"/api/v1/agents/{first['id']}/capabilities/{grant['id']}",
        headers=headers(token), json={},
    )
    task = client.post(
        f"/api/v1/agents/{first['id']}/tasks", headers=headers(token),
        json={"title": "Erase task", "expires_at": expiry()},
    ).json()
    client.post(
        f"/api/v1/agents/{second['id']}/messages", headers=headers(token),
        json={"recipient_agent_id": first["id"], "task_id": task["id"],
              "payload": {"message": "Erase"}},
    )
    state = get_app_state()
    owner = state.identity.resolve_token(token)
    state.identity.delete_user(owner["id"])
    connection = state.database.connect()
    for table in (
        "agent_capability_grants", "agent_capability_revocations",
        "agent_tasks", "agent_task_events", "agent_messages",
        "agent_control_events",
    ):
        assert connection.execute(
            f"SELECT 1 FROM {table} WHERE user_id=?", (owner["id"],)
        ).fetchone() is None


def test_capability_catalog_is_versioned_and_non_executable(client):
    token = owner_token(client, "control-catalog@example.com")
    response = client.get("/api/v1/agent-capabilities/catalog",
                          headers=headers(token))
    assert response.status_code == 200
    assert response.json()["version"] == 1
    assert "notes.read" in response.json()["capabilities"]
    assert response.json()["execution_enabled"] is False


def test_database_rejects_grant_mutation_and_unrecorded_task_transition(client):
    token = owner_token(client, "control-db-guards@example.com")
    agent = create_active_agent(client, token, "DB guard agent")
    grant = client.post(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=headers(token), json={"capability": "notes.write"},
    ).json()
    task = client.post(
        f"/api/v1/agents/{agent['id']}/tasks", headers=headers(token),
        json={"title": "Guarded task", "capability_ceiling": ["notes.write"],
              "expires_at": expiry()},
    ).json()
    state = get_app_state()
    with pytest.raises(sqlite3.IntegrityError, match="grants are immutable"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE agent_capability_grants SET capability='files.read' WHERE id=?",
                (grant["id"],),
            )
    with pytest.raises(sqlite3.IntegrityError, match="requires matching event"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE agent_tasks SET status='completed' WHERE id=?",
                (task["id"],),
            )
    with pytest.raises(sqlite3.IntegrityError, match="task definition is immutable"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE agent_tasks SET title='Changed' WHERE id=?",
                (task["id"],),
            )
    event = state.database.connect().execute(
        "SELECT id FROM agent_task_events WHERE task_id=?", (task["id"],)
    ).fetchone()
    with pytest.raises(sqlite3.IntegrityError, match="task events are immutable"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE agent_task_events SET event_type='failed' WHERE id=?",
                (event["id"],),
            )

def test_text_generation_capability_is_owner_grantable(client):
    token = owner_token(client, "control-text-generation@example.com")
    agent = create_active_agent(client, token, "Local generation agent")
    response = client.post(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=headers(token),
        json={"capability": "text_generation"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["capability"] == "text_generation"

