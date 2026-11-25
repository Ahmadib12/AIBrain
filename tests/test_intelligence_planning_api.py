from fastapi.testclient import TestClient

from backend.app.main import app


def test_planning_preview_returns_bounded_plan_without_execution():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/intelligence/plan",
            json={"text": "Explain how DNS works"},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["intent"]["kind"] == "inform"
    assert body["assessment"]["execution_permitted"] is False
    assert 1 <= len(body["plan"]["tasks"]) <= 20


def test_planning_preview_marks_consequential_intent_for_authorization():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/intelligence/plan",
            json={"text": "Send an email to my manager"},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["intent"]["kind"] == "control"
    assert body["assessment"]["requires_authorization"] is True
    assert body["assessment"]["execution_permitted"] is False


def test_planning_preview_rejects_unknown_request_fields():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/intelligence/plan",
            json={"text": "Explain DNS", "execute": True},
        )
    assert response.status_code == 422
