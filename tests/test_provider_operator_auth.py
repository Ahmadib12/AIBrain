from fastapi.testclient import TestClient

PROTECTED_ROUTES = (
    ("GET", "/api/v1/providers"),
    ("GET", "/api/v1/providers/status"),
    ("POST", "/api/v1/providers/health/mock"),
)
TEST_OPERATOR_TOKEN = "test-provider-operator-token-32chars"


def send(client: TestClient, method: str, path: str, headers=None):
    return client.request(method, path, headers=headers)


def test_operational_routes_reject_missing_operator_token(client, monkeypatch):
    monkeypatch.setenv("AIBRAIN_PROVIDER_OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)
    for method, path in PROTECTED_ROUTES:
        response = send(client, method, path)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "OPERATOR_UNAUTHORIZED"


def test_operational_routes_reject_incorrect_operator_token(client, monkeypatch):
    monkeypatch.setenv("AIBRAIN_PROVIDER_OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)
    headers = {"X-AIBrain-Operator-Token": "incorrect-token"}
    for method, path in PROTECTED_ROUTES:
        response = send(client, method, path, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "OPERATOR_UNAUTHORIZED"


def test_operational_routes_fail_closed_without_operator_configuration(client, monkeypatch):
    monkeypatch.delenv("AIBRAIN_PROVIDER_OPERATOR_TOKEN", raising=False)
    for method, path in PROTECTED_ROUTES:
        response = send(client, method, path)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "OPERATOR_AUTH_NOT_CONFIGURED"


def test_valid_operator_token_allows_provider_operations(client, monkeypatch):
    monkeypatch.setenv("AIBRAIN_PROVIDER_OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)
    headers = {"X-AIBrain-Operator-Token": TEST_OPERATOR_TOKEN}
    for method, path in PROTECTED_ROUTES:
        response = send(client, method, path, headers=headers)
        assert response.status_code == 200


def test_provider_chat_remains_public(client):
    response = client.post(
        "/api/v1/providers/chat",
        json={"messages": [{"role": "user", "content": "Hello"}]},
    )
    assert response.status_code == 200
