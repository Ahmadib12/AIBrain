from uuid import uuid4

from backend.app.api.v1 import auth as auth_api
from backend.app.auth.rate_limit import LoginRateLimiter


def registration_payload():
    return {
        "email": f"registration-{uuid4().hex}@example.com",
        "password": "safe-password-123",
        "display_name": "Registration Test",
    }


def test_registration_is_limited_by_client_ip_not_email_or_forwarded_header(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        auth_api,
        "_registration_rate_limiter",
        LoginRateLimiter(limit=2, window_seconds=300),
    )

    first = client.post(
        "/api/v1/auth/register",
        json=registration_payload(),
        headers={"X-Forwarded-For": "198.51.100.10"},
    )
    second = client.post(
        "/api/v1/auth/register",
        json=registration_payload(),
        headers={"X-Forwarded-For": "203.0.113.20"},
    )
    third = client.post(
        "/api/v1/auth/register",
        json=registration_payload(),
        headers={"X-Forwarded-For": "192.0.2.30"},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["error"]["code"] == "REGISTRATION_RATE_LIMITED"


def test_registration_attempts_count_even_when_email_is_already_registered(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        auth_api,
        "_registration_rate_limiter",
        LoginRateLimiter(limit=2, window_seconds=300),
    )
    payload = registration_payload()

    first = client.post("/api/v1/auth/register", json=payload)
    duplicate = client.post("/api/v1/auth/register", json=payload)
    third = client.post(
        "/api/v1/auth/register",
        json=registration_payload(),
    )

    assert first.status_code == 200
    assert duplicate.status_code == 400
    assert third.status_code == 429
