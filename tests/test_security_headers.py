from fastapi.testclient import TestClient

from backend.app.main import app


EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


def assert_security_headers(response):
    for name, value in EXPECTED_HEADERS.items():
        assert response.headers.get(name) == value


def test_security_headers_are_present_on_normal_response():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert_security_headers(response)


def test_security_headers_are_present_on_api_error():
    with TestClient(app) as client:
        response = client.get("/api/v1/providers")

    assert response.status_code in (401, 503)
    assert_security_headers(response)


def test_security_headers_are_present_on_oversized_request():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/providers/chat",
            json={"messages": [{"role": "user", "content": "x" * 1_100_000}]},
        )

    assert response.status_code == 413
    assert_security_headers(response)


def test_existing_security_header_is_not_duplicated():
    with TestClient(app) as client:
        response = client.get("/health")

    assert sum(
        1 for name in response.headers
        if name.lower() == "x-frame-options"
    ) == 1
