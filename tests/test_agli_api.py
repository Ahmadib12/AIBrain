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
