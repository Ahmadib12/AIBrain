from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.api.v1.tools import tool_registry
from backend.app.api.v1.agent_execution import _reject_unbound_integration_actions
from backend.app.app_state import get_app_state
from backend.app.main import app
from backend.app.tools import ToolContract, ToolRisk


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def owner_token(client: TestClient, email: str) -> str:
    registered = client.post("/api/v1/auth/register", json={
        "email": email, "password": "safe-password-123",
        "display_name": "Execution Owner",
    })
    assert registered.status_code == 200
    response = client.post("/api/v1/auth/login", json={
        "email": email, "password": "safe-password-123",
    })
    assert response.status_code == 200
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_agent(client: TestClient, token: str) -> dict:
    response = client.post("/api/v1/agents", headers=auth(token),
                           json={"name": "Governed runner"})
    assert response.status_code == 201
    agent = response.json()
    active = client.patch(
        f"/api/v1/agents/{agent['id']}/lifecycle",
        headers=auth(token), json={"status": "active"},
    )
    assert active.status_code == 200
    return agent


def expires() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def create_task(client: TestClient, token: str, agent_id: str,
                ceiling: list[str] | None = None) -> dict:
    response = client.post(
        f"/api/v1/agents/{agent_id}/tasks",
        headers=auth(token),
        json={
            "title": "Run a bounded task",
            "goal": "Perform explicitly authorized read-only work",
            "context": {},
            "capability_ceiling": ceiling or [],
            "expires_at": expires(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_run_requires_explicit_owner_authorization_and_executes_read_only(
    client: TestClient,
):
    token = owner_token(client, "m9-run-owner@example.com")
    agent = create_agent(client, token)
    task = create_task(client, token, agent["id"])
    state = get_app_state()
    user_id = state.identity.resolve_token(token)["id"]
    before = state.database.connect().execute(
        "SELECT COUNT(*) FROM tool_requests WHERE user_id=?", (user_id,)
    ).fetchone()[0]

    proposed = client.post(
        f"/api/v1/agent-tasks/{task['id']}/runs",
        headers=auth(token),
        json={"actions": [{"tool_id": "echo", "arguments": {"text": "safe result"}}]},
    )
    assert proposed.status_code == 201, proposed.text
    run = proposed.json()
    assert run["status"] == "proposed"
    assert run["plan_digest"]
    assert run["steps"][0]["status"] == "pending"

    blocked = client.post(
        f"/api/v1/agent-runs/{run['id']}/execute", headers=auth(token)
    )
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "AGENT_RUN_NOT_EXECUTABLE"

    still_before = state.database.connect().execute(
        "SELECT COUNT(*) FROM tool_requests WHERE user_id=?", (user_id,)
    ).fetchone()[0]
    assert still_before == before

    authorized = client.post(
        f"/api/v1/agent-runs/{run['id']}/authorize", headers=auth(token)
    )
    assert authorized.status_code == 200, authorized.text
    assert authorized.json()["status"] == "authorized"

    executed = client.post(
        f"/api/v1/agent-runs/{run['id']}/execute", headers=auth(token)
    )
    assert executed.status_code == 200, executed.text
    result = executed.json()
    assert result["status"] == "completed"
    assert result["steps"][0]["status"] == "completed"
    assert result["steps"][0]["result"]["result"]["text"] == "safe result"
    events = client.get(
        f"/api/v1/agent-runs/{run['id']}/events", headers=auth(token)
    )
    assert events.status_code == 200
    assert [item["event_type"] for item in events.json()] == [
        "created", "authorized", "started", "step_started", "step_completed", "completed"
    ]


def test_run_rejects_state_changing_and_consequential_tools(
    client: TestClient, monkeypatch: pytest.MonkeyPatch,
):
    token = owner_token(client, "m9-risk-owner@example.com")
    agent = create_agent(client, token)
    task = create_task(client, token, agent["id"])
    contract = ToolContract(
        tool_id="m9-state-change",
        name="State change",
        description="Must remain blocked",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={"type": "object", "properties": {}, "required": [],
                      "additionalProperties": False},
        output_schema={"type": "object"},
    )
    monkeypatch.setitem(tool_registry._tools, contract.tool_id, contract)
    response = client.post(
        f"/api/v1/agent-tasks/{task['id']}/runs",
        headers=auth(token),
        json={"actions": [{"tool_id": contract.tool_id, "arguments": {}}]},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AGENT_RUN_NOT_PERMITTED"


def test_revoked_capability_blocks_execution_after_run_authorization(
    client: TestClient,
):
    token = owner_token(client, "m9-revocation-owner@example.com")
    agent = create_agent(client, token)
    grant = client.post(
        f"/api/v1/agents/{agent['id']}/capabilities",
        headers=auth(token), json={"capability": "research.read"},
    )
    assert grant.status_code == 201
    task = create_task(client, token, agent["id"], ["research.read"])
    run_response = client.post(
        f"/api/v1/agent-tasks/{task['id']}/runs",
        headers=auth(token),
        json={"actions": [{
            "tool_id": "echo", "arguments": {"text": "should not execute"},
            "required_capability": "research.read",
        }]},
    )
    assert run_response.status_code == 201, run_response.text
    run_id = run_response.json()["id"]
    authorized = client.post(
        f"/api/v1/agent-runs/{run_id}/authorize", headers=auth(token)
    )
    assert authorized.status_code == 200

    revoked = client.request(
        "DELETE",
        f"/api/v1/agents/{agent['id']}/capabilities/{grant.json()['id']}",
        headers=auth(token), json={"reason": "Revoked before execution"},
    )
    assert revoked.status_code == 200

    blocked = client.post(
        f"/api/v1/agent-runs/{run_id}/execute", headers=auth(token)
    )
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "AGENT_RUN_EXECUTION_REJECTED"
    persisted = client.get(f"/api/v1/agent-runs/{run_id}", headers=auth(token))
    assert persisted.json()["status"] == "authorized"


def test_run_is_owner_scoped_and_cancellation_is_terminal(client: TestClient):
    owner = owner_token(client, "m9-scope-owner@example.com")
    other = owner_token(client, "m9-scope-other@example.com")
    agent = create_agent(client, owner)
    task = create_task(client, owner, agent["id"])
    created = client.post(
        f"/api/v1/agent-tasks/{task['id']}/runs",
        headers=auth(owner),
        json={"actions": [{"tool_id": "echo", "arguments": {"text": "cancel me"}}]},
    )
    assert created.status_code == 201
    run_id = created.json()["id"]

    foreign = client.get(f"/api/v1/agent-runs/{run_id}", headers=auth(other))
    assert foreign.status_code == 404

    cancelled = client.post(
        f"/api/v1/agent-runs/{run_id}/cancel", headers=auth(owner)
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    repeated = client.post(
        f"/api/v1/agent-runs/{run_id}/authorize", headers=auth(owner)
    )
    assert repeated.status_code == 409


def test_run_definition_and_event_ledger_are_database_protected(client: TestClient):
    token = owner_token(client, "m9-integrity-owner@example.com")
    agent = create_agent(client, token)
    task = create_task(client, token, agent["id"])
    run = client.post(
        f"/api/v1/agent-tasks/{task['id']}/runs",
        headers=auth(token),
        json={"actions": [{"tool_id": "echo", "arguments": {"text": "immutable"}}]},
    ).json()
    state = get_app_state()
    with pytest.raises(Exception, match="agent run definition is immutable"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE agent_runs SET plan_digest=? WHERE id=?",
                ("0" * 64, run["id"]),
            )
    event_id = state.database.connect().execute(
        "SELECT id FROM agent_run_events WHERE run_id=? LIMIT 1", (run["id"],)
    ).fetchone()["id"]
    with pytest.raises(Exception, match="agent run events are immutable"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE agent_run_events SET event_type='tampered' WHERE id=?",
                (event_id,),
            )


def test_account_erasure_cascades_agent_run_records(client: TestClient):
    token = owner_token(client, "m9-erasure-owner@example.com")
    agent = create_agent(client, token)
    task = create_task(client, token, agent["id"])
    run = client.post(
        f"/api/v1/agent-tasks/{task['id']}/runs",
        headers=auth(token),
        json={"actions": [{"tool_id": "echo", "arguments": {"text": "erase"}}]},
    )
    assert run.status_code == 201
    state = get_app_state()
    user_id = state.identity.resolve_token(token)["id"]

    deleted = client.delete("/api/v1/auth/me", headers=auth(token))
    assert deleted.status_code == 200

    for table in ("agent_runs", "agent_run_steps", "agent_run_events"):
        remaining = state.database.connect().execute(
            f"SELECT 1 FROM {table} WHERE user_id=?", (user_id,)
        ).fetchone()
        assert remaining is None


def test_expired_unstarted_runs_are_reconciled(client: TestClient, monkeypatch):
    import backend.app.persistence.agent_execution as execution_module

    token = owner_token(client, "m9-expiry-owner@example.com")
    agent = create_agent(client, token)
    task = create_task(client, token, agent["id"])
    run = client.post(
        f"/api/v1/agent-tasks/{task['id']}/runs",
        headers=auth(token),
        json={"actions": [{"tool_id": "echo", "arguments": {"text": "expire"}}]},
    )
    assert run.status_code == 201
    monkeypatch.setattr(
        execution_module, "_now",
        lambda: datetime.now(timezone.utc) + timedelta(minutes=16),
    )
    reconciled = client.post(
        "/api/v1/agent-runs/reconcile-expired", headers=auth(token)
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["expired"] == 1
    expired = client.get(
        f"/api/v1/agent-runs/{run.json()['id']}", headers=auth(token)
    )
    assert expired.json()["status"] == "expired"


def test_m9_agent_run_rejects_registered_integration_tool_ids():
    class IntegrationCatalog:
        def resolve_tool(self, tool_id):
            return ("calendar", object()) if tool_id == "calendar.events.read" else None

    class State:
        integrations = IntegrationCatalog()

    with pytest.raises(PermissionError, match="bound asynchronous orchestrator"):
        _reject_unbound_integration_actions(
            [{"tool_id": "calendar.events.read"}], State()
        )

    _reject_unbound_integration_actions(
        [{"tool_id": "echo"}], State()
    )


def test_integration_agent_run_persists_immutable_owner_scope_binding(
    client: TestClient,
):
    from backend.app.tools.integrations import IntegrationManifest, IntegrationTool

    token = owner_token(client, "m10-binding-owner@example.com")
    agent = create_agent(client, token)
    task = create_task(client, token, agent["id"])
    state = get_app_state()
    user_id = state.identity.resolve_token(token)["id"]

    contract = ToolContract(
        tool_id="catalog.search",
        name="Catalog search",
        description="Read catalog entries",
        risk=ToolRisk.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 100}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )
    state.integrations.register(IntegrationManifest(
        integration_id="catalog",
        name="Catalog",
        description="Owner connected catalog",
        version="1",
        tools=(IntegrationTool(contract, ("catalog.read",)),),
    ))
    connection = state.integration_connections.create_pending(
        user_id, "catalog", ["catalog.read"], consent_version="v1"
    )
    now = datetime.now(timezone.utc).isoformat()
    with state.database.transaction(immediate=True):
        state.database.connect().execute(
            """INSERT INTO integration_secrets
               (secret_ref,user_id,connection_id,integration_id,nonce,ciphertext,
                key_version,created_at,updated_at)
               VALUES ('vault-ref:m10-test',?,?,?, ?, ?,1,?,?)""",
            (user_id, connection["id"], "catalog", b"n" * 12, b"c" * 16, now, now),
        )
        state.database.connect().execute(
            """UPDATE integration_connections
               SET status='active',verified_at=?,secret_ref='vault-ref:m10-test',
                   expires_at=?,updated_at=? WHERE id=?""",
            (now, (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
             now, connection["id"]),
        )
        state.database.connect().execute(
            """UPDATE integration_connection_grants
               SET status='active',expires_at=?
               WHERE connection_id=? AND user_id=?""",
            ((datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
             connection["id"], user_id),
        )

    run = state.agent_execution.create_integration_run(
        user_id,
        task["id"],
        [{
            "tool_id": "catalog.search",
            "arguments": {"query": "invoices"},
            "connection_id": connection["id"],
        }],
        state.integrations,
        state.integration_connections,
    )
    assert run["status"] == "proposed"
    assert run["steps"][0]["tool_id"] == "catalog.search"
    bindings = state.agent_execution.list_integration_bindings(user_id, run["id"])
    assert len(bindings) == 1
    assert bindings[0]["connection_id"] == connection["id"]
    assert bindings[0]["integration_id"] == "catalog"
    assert bindings[0]["manifest_version"] == "1"
    assert bindings[0]["required_scopes"] == ["catalog.read"]
    assert bindings[0]["contract_fingerprint"] == run["steps"][0]["contract_fingerprint"]

    authorized = state.agent_execution.authorize_run(
        user_id, run["id"], state.integrations, state.integration_connections
    )
    assert authorized["status"] == "authorized"

    binding_step = bindings[0]["step_id"]
    with pytest.raises(Exception, match="integration bindings are immutable"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                """UPDATE agent_run_integration_bindings
                   SET manifest_version='2' WHERE step_id=?""",
                (binding_step,),
            )
    with pytest.raises(Exception, match="may only be deleted during account erasure"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "DELETE FROM agent_run_integration_bindings WHERE step_id=?",
                (binding_step,),
            )

    # A revoked owner connection invalidates the previously authorized binding.
    state.integration_connections.revoke(user_id, connection["id"])
    raw_run = state.agent_execution._raw_run(user_id, run["id"])
    with pytest.raises(PermissionError, match="no longer active"):
        state.agent_execution._validate_integration_bindings(
            user_id, raw_run, state.integrations, state.integration_connections
        )

    # The synchronous M9 executor must never execute integration-bound runs.
    with pytest.raises(PermissionError, match="dedicated asynchronous orchestrator"):
        state.agent_execution.execute_run(user_id, run["id"], None, None)
