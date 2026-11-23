import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.app_state import get_app_state
from backend.app.main import app


@pytest.fixture
def client():
    get_app_state()
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(client: TestClient) -> str:
    email = f"webauthn-api-{uuid.uuid4().hex}@example.com"

    registered = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "safe-password-123",
            "display_name": "Passkey API Test",
        },
    )
    assert registered.status_code == 200

    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "safe-password-123",
        },
    )
    assert login.status_code == 200
    return login.json()["access_token"]


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_passkey_registration_endpoints_require_authentication(client):
    options = client.post("/api/v1/auth/passkeys/registration/options")
    verify = client.post(
        "/api/v1/auth/passkeys/registration/verify",
        json={
            "challenge_record_id": "challenge-id",
            "credential": {},
        },
    )

    assert options.status_code == 401
    assert verify.status_code == 401


def test_passkey_registration_options_use_authenticated_identity(
    client,
    monkeypatch,
):
    token = register_and_login(client)
    state = get_app_state()
    captured = {}

    def fake_create_registration_options(**kwargs):
        captured.update(kwargs)
        return {
            "challenge_record_id": "challenge-id",
            "options": {"challenge": "test-challenge"},
        }

    monkeypatch.setattr(
        state.webauthn_service,
        "create_registration_options",
        fake_create_registration_options,
    )

    response = client.post(
        "/api/v1/auth/passkeys/registration/options",
        headers=headers(token),
        json={"password": "safe-password-123"},
    )

    assert response.status_code == 200
    assert response.json()["challenge_record_id"] == "challenge-id"
    assert captured["user_id"]
    assert captured["user_name"].endswith("@example.com")
    assert captured["user_display_name"] == "Passkey API Test"


def test_passkey_registration_verify_returns_only_safe_metadata(
    client,
    monkeypatch,
):
    token = register_and_login(client)
    state = get_app_state()
    captured = {}

    def fake_verify_registration(**kwargs):
        captured.update(kwargs)
        return {
            "id": "internal-record-id",
            "user_id": "internal-user-id",
            "credential_id": "sensitive-credential-id",
            "public_key": b"sensitive-public-key",
            "name": "My passkey",
            "device_type": "single_device",
            "backed_up": False,
            "created_at": "2026-11-22T12:00:00+00:00",
            "transports": ["internal"],
            "sign_count": 0,
        }

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_registration",
        fake_verify_registration,
    )

    response = client.post(
        "/api/v1/auth/passkeys/registration/verify",
        headers=headers(token),
        json={
            "challenge_record_id": "challenge-id",
            "credential": {"response": {"clientDataJSON": "test"}},
            "name": "My passkey",
        },
    )

    assert response.status_code == 200
    assert captured["user_id"]
    assert captured["challenge_record_id"] == "challenge-id"
    assert captured["name"] == "My passkey"

    body = response.json()
    assert body["passkey"]["name"] == "My passkey"
    assert body["passkey"]["device_type"] == "single_device"
    assert body["passkey"]["transports"] == ["internal"]

    serialized = response.text
    assert "sensitive-public-key" not in serialized
    assert "sensitive-credential-id" not in serialized
    assert "internal-user-id" not in serialized


def test_passkey_registration_options_return_503_when_disabled(
    client,
    monkeypatch,
):
    token = register_and_login(client)
    state = get_app_state()

    def disabled():
        raise PermissionError("WebAuthn is not enabled or configured")

    monkeypatch.setattr(state.webauthn_service, "_require_enabled", disabled)

    response = client.post(
        "/api/v1/auth/passkeys/registration/options",
        headers=headers(token),
        json={"password": "safe-password-123"},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "WEBAUTHN_UNAVAILABLE"


def test_passkey_registration_rejects_extra_request_fields(client):
    token = register_and_login(client)

    response = client.post(
        "/api/v1/auth/passkeys/registration/verify",
        headers=headers(token),
        json={
            "challenge_record_id": "challenge-id",
            "credential": {},
            "user_id": "attacker-selected-user",
        },
    )

    assert response.status_code == 422




def test_passkey_registration_options_reject_wrong_password_without_challenge(
    client,
    monkeypatch,
):
    token = register_and_login(client)
    state = get_app_state()
    called = False

    def unexpected_create_registration_options(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("Registration options must not be created")

    monkeypatch.setattr(
        state.webauthn_service,
        "create_registration_options",
        unexpected_create_registration_options,
    )

    response = client.post(
        "/api/v1/auth/passkeys/registration/options",
        headers=headers(token),
        json={"password": "incorrect-password"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "REAUTHENTICATION_REQUIRED"
    assert called is False


def test_passkey_registration_options_require_password(client):
    token = register_and_login(client)

    response = client.post(
        "/api/v1/auth/passkeys/registration/options",
        headers=headers(token),
    )

    assert response.status_code == 422


def test_passkey_registration_options_reject_extra_fields(client):
    token = register_and_login(client)

    response = client.post(
        "/api/v1/auth/passkeys/registration/options",
        headers=headers(token),
        json={
            "password": "safe-password-123",
            "user_id": "attacker-selected-user",
        },
    )

    assert response.status_code == 422

def create_passkey_authentication_api_account(client):
    email = f"passkey-login-{uuid.uuid4().hex}@example.com"
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "safe-password-123",
            "display_name": "Passkey Login Test",
        },
    )
    assert response.status_code == 200
    return email


def test_passkey_authentication_options_use_email_account(client, monkeypatch):
    email = create_passkey_authentication_api_account(client)
    state = get_app_state()
    captured = {}

    def fake_options(**kwargs):
        captured.update(kwargs)
        return {
            "challenge_record_id": "auth-challenge",
            "options": {"challenge": "test-challenge"},
        }

    monkeypatch.setattr(
        state.webauthn_service,
        "create_authentication_options",
        fake_options,
    )

    response = client.post(
        "/api/v1/auth/passkeys/authentication/options",
        json={"email": email.upper()},
    )

    assert response.status_code == 200
    assert response.json()["challenge_record_id"] == "auth-challenge"
    assert captured["user_id"] == state.identity.get_user_by_email(email)["id"]


def test_passkey_authentication_verify_creates_normal_session(
    client,
    monkeypatch,
):
    email = create_passkey_authentication_api_account(client)
    state = get_app_state()
    captured = {}

    def fake_verify(**kwargs):
        captured.update(kwargs)
        return {"id": "verified-passkey"}

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_authentication",
        fake_verify,
    )

    response = client.post(
        "/api/v1/auth/passkeys/authentication/verify",
        json={
            "email": email,
            "challenge_record_id": "auth-challenge",
            "assertion": {"id": "verified-assertion"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["user"]["email"] == email
    assert captured["user_id"] == body["user"]["id"]
    assert captured["challenge_record_id"] == "auth-challenge"
    assert captured["assertion"]["id"] == "verified-assertion"

    me = client.get(
        "/api/v1/auth/me",
        headers=headers(body["access_token"]),
    )
    assert me.status_code == 200
    assert me.json()["user"]["id"] == body["user"]["id"]


def test_failed_passkey_verification_does_not_create_session(
    client,
    monkeypatch,
):
    email = create_passkey_authentication_api_account(client)
    state = get_app_state()
    user = state.identity.get_user_by_email(email)

    def reject_assertion(**kwargs):
        raise PermissionError("Invalid cryptographic assertion")

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_authentication",
        reject_assertion,
    )

    before = state.identity.database.connect().execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
        (user["id"],),
    ).fetchone()[0]

    response = client.post(
        "/api/v1/auth/passkeys/authentication/verify",
        json={
            "email": email,
            "challenge_record_id": "invalid-challenge",
            "assertion": {"id": "invalid-assertion"},
        },
    )

    after = state.identity.database.connect().execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
        (user["id"],),
    ).fetchone()[0]

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_PASSKEY_CREDENTIALS"
    assert "access_token" not in response.json()
    assert after == before


def test_unknown_account_and_account_without_passkeys_look_the_same(
    client,
    monkeypatch,
):
    email = create_passkey_authentication_api_account(client)
    state = get_app_state()

    def no_passkeys(**kwargs):
        raise PermissionError("No active passkeys are registered")

    monkeypatch.setattr(
        state.webauthn_service,
        "create_authentication_options",
        no_passkeys,
    )

    existing = client.post(
        "/api/v1/auth/passkeys/authentication/options",
        json={"email": email},
    )
    unknown = client.post(
        "/api/v1/auth/passkeys/authentication/options",
        json={"email": f"unknown-{uuid.uuid4().hex}@example.com"},
    )

    assert existing.status_code == unknown.status_code == 401
    assert existing.json() == unknown.json()


def test_passkey_authentication_returns_503_when_disabled(
    client,
    monkeypatch,
):
    email = create_passkey_authentication_api_account(client)
    state = get_app_state()

    def disabled(**kwargs):
        raise PermissionError("WebAuthn is not enabled or configured")

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_authentication",
        disabled,
    )

    response = client.post(
        "/api/v1/auth/passkeys/authentication/verify",
        json={
            "email": email,
            "challenge_record_id": "challenge-id",
            "assertion": {},
        },
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "WEBAUTHN_UNAVAILABLE"


def test_passkey_authentication_rejects_extra_identity_fields(client):
    email = create_passkey_authentication_api_account(client)

    response = client.post(
        "/api/v1/auth/passkeys/authentication/verify",
        json={
            "email": email,
            "challenge_record_id": "challenge-id",
            "assertion": {},
            "user_id": "attacker-selected-user",
        },
    )

    assert response.status_code == 422

def test_passkey_authentication_options_rate_limit_successful_requests(
    client,
    monkeypatch,
):
    from backend.app.auth.rate_limit import LoginRateLimiter
    import backend.app.api.v1.auth as auth_module

    email = create_passkey_authentication_api_account(client)
    state = get_app_state()
    limiter = LoginRateLimiter(limit=2, window_seconds=300)
    monkeypatch.setattr(auth_module, "_login_rate_limiter", limiter)

    calls = []

    def fake_options(**kwargs):
        calls.append(kwargs)
        return {
            "challenge_record_id": f"auth-challenge-{len(calls)}",
            "options": {"challenge": "test-challenge"},
        }

    monkeypatch.setattr(
        state.webauthn_service,
        "create_authentication_options",
        fake_options,
    )

    first = client.post(
        "/api/v1/auth/passkeys/authentication/options",
        json={"email": email},
    )
    second = client.post(
        "/api/v1/auth/passkeys/authentication/options",
        json={"email": email},
    )
    third = client.post(
        "/api/v1/auth/passkeys/authentication/options",
        json={"email": email},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["error"]["code"] == "LOGIN_RATE_LIMITED"
    assert len(calls) == 2

