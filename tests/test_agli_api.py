from uuid import uuid4

from fastapi.testclient import TestClient


def test_list_languages(client: TestClient) -> None:
    response = client.get("/api/v1/agli/languages")
    assert response.status_code == 200
    assert {entry["code"] for entry in response.json()} >= {"en", "es", "fr", "ar"}


def test_lookup_language(client: TestClient) -> None:
    response = client.get("/api/v1/agli/languages/en")
    assert response.status_code == 200
    body = response.json()
    assert body["code"] == "en"
    assert body["native_name"] == "English"
    assert body["script"]["direction"] == "ltr"


def test_lookup_unknown_language(client: TestClient) -> None:
    response = client.get("/api/v1/agli/languages/xx")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "LANGUAGE_NOT_FOUND"


def test_language_execution_requires_authenticated_session(client: TestClient) -> None:
    response = client.post(
        "/api/v1/agli/language/detect",
        json={"text": "hello"},
    )
    assert response.status_code == 401


def test_language_execution_fails_closed_without_runtime_engine(
    client: TestClient,
) -> None:
    email = f"agli-{uuid4().hex}@example.com"
    password = "test-password-strong"
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert registered.status_code == 200

    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    detection = client.post(
        "/api/v1/agli/language/detect",
        json={"text": "hello"},
        headers=headers,
    )
    translation = client.post(
        "/api/v1/agli/language/translate",
        json={"text": "Hello", "source_language": "en", "target_language": "fr"},
        headers=headers,
    )
    assert detection.status_code == 503
    assert detection.json()["error"]["code"] == "LANGUAGE_DETECTION_UNAVAILABLE"
    assert translation.status_code == 503
    assert translation.json()["error"]["code"] == "TEXT_TRANSLATION_UNAVAILABLE"
