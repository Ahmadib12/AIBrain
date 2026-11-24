import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.app_state import get_app_state


def _register(client: TestClient, email: str) -> str:
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "safe-password-123"},
    )
    assert registered.status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "safe-password-123"},
    )
    assert login.status_code == 200
    return login.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _proposal(client: TestClient, token: str) -> str:
    response = client.post(
        "/api/v1/personal/learning/adaptations",
        headers=_headers(token),
        json={
            "proposal": {
                "scope": "response_style",
                "change": {"verbosity": "concise"},
                "rationale": "User repeatedly requests concise technical instructions",
            }
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "pending"
    assert body["execution_permitted"] is False
    assert body["expires_at"]
    return body["id"]


def test_learning_adaptation_approval_evaluation_and_audit_trail(client):
    token = _register(client, "m7-lifecycle@example.com")
    adaptation_id = _proposal(client, token)

    approved = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=_headers(token),
        json={"status": "approved", "reason": "Reviewed and accepted by owner"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["execution_permitted"] is False

    evaluation = client.post(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}/evaluations",
        headers=_headers(token),
        json={
            "outcome": "improved",
            "metric": "user_correction_rate",
            "baseline_value": 0.4,
            "observed_value": 0.2,
            "confidence": 0.75,
            "evidence": {"sample_size": 10, "window": "one_week"},
        },
    )
    assert evaluation.status_code == 200
    assert evaluation.json()["source"] == "user_reported"
    assert evaluation.json()["outcome"] == "improved"

    listed = client.get(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}/evaluations",
        headers=_headers(token),
    )
    events = client.get(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}/events",
        headers=_headers(token),
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert events.status_code == 200
    assert [item["event_type"] for item in events.json()] == [
        "proposed", "approved", "evaluated"
    ]
    proposal_details = events.json()[0]["details"]
    assert proposal_details["source"] == "user_submitted"
    assert len(proposal_details["proposal_sha256"]) == 64


def test_learning_adaptation_terminal_decisions_cannot_be_reversed(client):
    token = _register(client, "m7-terminal@example.com")
    adaptation_id = _proposal(client, token)

    rejected = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=_headers(token),
        json={"status": "rejected", "reason": "Not useful"},
    )
    assert rejected.status_code == 200

    reapproved = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=_headers(token),
        json={"status": "approved"},
    )
    assert reapproved.status_code == 409
    assert reapproved.json()["error"]["code"] == "INVALID_ADAPTATION_TRANSITION"

    state = get_app_state()
    with pytest.raises(sqlite3.IntegrityError):
        state.database.connect().execute(
            "UPDATE adaptations SET status = 'approved' WHERE id = ?",
            (adaptation_id,),
        )


def test_learning_records_are_owner_scoped(client):
    owner_token = _register(client, "m7-owner@example.com")
    other_token = _register(client, "m7-other@example.com")
    adaptation_id = _proposal(client, owner_token)

    for suffix in ("events", "evaluations"):
        response = client.get(
            f"/api/v1/personal/learning/adaptations/{adaptation_id}/{suffix}",
            headers=_headers(other_token),
        )
        assert response.status_code == 404


def test_learning_adaptation_expires_and_is_audited(client):
    token = _register(client, "m7-expiry@example.com")
    adaptation_id = _proposal(client, token)
    approved = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=_headers(token),
        json={"status": "approved"},
    )
    assert approved.status_code == 200
    state = get_app_state()

    with state.database.transaction():
        state.database.connect().execute(
            "UPDATE adaptations SET expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", adaptation_id),
        )

    response = client.get(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=_headers(token),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "expired"

    evaluation = client.post(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}/evaluations",
        headers=_headers(token),
        json={
            "outcome": "improved",
            "metric": "latency",
            "baseline_value": 10.0,
            "observed_value": 8.0,
            "confidence": 0.8,
            "evidence": {"source": "manual"},
        },
    )
    assert evaluation.status_code == 400

    events = client.get(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}/events",
        headers=_headers(token),
    )
    assert [item["event_type"] for item in events.json()] == [
        "proposed", "approved", "expired"
    ]


def test_learning_evaluations_require_approved_adaptation(client):
    token = _register(client, "m7-pending-eval@example.com")
    adaptation_id = _proposal(client, token)
    rejected_by_api = client.post(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}/evaluations",
        headers=_headers(token),
        json={
            "outcome": "improved",
            "metric": "latency",
            "baseline_value": 10.0,
            "observed_value": 8.0,
            "confidence": 0.8,
            "evidence": {"source": "manual"},
        },
    )
    assert rejected_by_api.status_code == 400
    assert rejected_by_api.json()["error"]["code"] == "INVALID_LEARNING_EVALUATION"

    state = get_app_state()
    user = state.identity.resolve_token(token)

    with pytest.raises(sqlite3.IntegrityError):
        state.database.connect().execute(
            """
            INSERT INTO learning_evaluations (
                id, user_id, adaptation_id, outcome, metric,
                baseline_value, observed_value, confidence,
                evidence_json, source, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "blocked-pending-evaluation",
                user["id"],
                adaptation_id,
                "improved",
                "latency",
                10.0,
                8.0,
                0.8,
                "{}",
                "user_reported",
                "2026-11-24T00:00:00+00:00",
            ),
        )


def test_learning_governance_history_is_immutable(client):
    token = _register(client, "m7-immutable@example.com")
    adaptation_id = _proposal(client, token)
    approved = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=_headers(token),
        json={"status": "approved"},
    )
    assert approved.status_code == 200
    evaluation = client.post(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}/evaluations",
        headers=_headers(token),
        json={
            "outcome": "no_change",
            "metric": "completion_rate",
            "baseline_value": 0.5,
            "observed_value": 0.5,
            "confidence": 0.5,
            "evidence": {"source": "manual_review"},
        },
    )
    assert evaluation.status_code == 200

    state = get_app_state()
    with pytest.raises(sqlite3.IntegrityError):
        state.database.connect().execute(
            "UPDATE learning_evaluations SET outcome = 'improved' WHERE id = ?",
            (evaluation.json()["id"],),
        )
    with pytest.raises(sqlite3.IntegrityError):
        state.database.connect().execute(
            "UPDATE learning_adaptation_events SET event_type = 'revoked' "
            "WHERE adaptation_id = ?",
            (adaptation_id,),
        )


def test_learning_adaptation_can_be_paused_resumed_and_revoked(client):
    token = _register(client, "m7-rollback@example.com")
    adaptation_id = _proposal(client, token)
    base = f"/api/v1/personal/learning/adaptations/{adaptation_id}"
    headers = _headers(token)

    for status in ("approved", "suspended", "approved", "revoked"):
        response = client.patch(
            base,
            headers=headers,
            json={"status": status, "reason": f"Owner selected {status}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == status
        assert response.json()["execution_permitted"] is False

    terminal = client.patch(
        base,
        headers=headers,
        json={"status": "approved"},
    )
    assert terminal.status_code == 409

    events = client.get(base + "/events", headers=headers)
    assert [item["event_type"] for item in events.json()] == [
        "proposed", "approved", "suspended", "approved", "revoked"
    ]
