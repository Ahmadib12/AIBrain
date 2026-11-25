import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.app_state import get_app_state


def _register_and_login(client: TestClient, label: str) -> tuple[str, str]:
    email = f"session-audit-{label}-{uuid.uuid4().hex}@example.com"
    password = "safe-password-123"
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
    return login.json()["access_token"], email


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_session_security_history_records_creation_and_revocation(client: TestClient):
    token, _ = _register_and_login(client, "lifecycle")

    before_logout = client.get(
        "/api/v1/auth/security-events", headers=_headers(token)
    )
    assert before_logout.status_code == 200
    created = before_logout.json()
    assert len(created) == 1
    assert created[0]["event_type"] == "session.created"
    assert created[0]["auth_method"] == "account"
    assert created[0]["device_id"] is None
    assert "token" not in created[0]
    assert "token_hash" not in created[0]

    logout = client.post("/api/v1/auth/logout", headers=_headers(token))
    assert logout.status_code == 200

    after_logout = client.get(
        "/api/v1/auth/security-events",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert after_logout.status_code == 401

    state = get_app_state()
    user = state.identity.get_user_by_email(_register_and_login(client, "lookup")[1])
    assert user is not None


def test_session_security_history_is_owner_scoped(client: TestClient):
    owner_token, _ = _register_and_login(client, "owner")
    other_token, _ = _register_and_login(client, "other")

    owner_events = client.get(
        "/api/v1/auth/security-events", headers=_headers(owner_token)
    )
    other_events = client.get(
        "/api/v1/auth/security-events", headers=_headers(other_token)
    )
    assert owner_events.status_code == 200
    assert len(owner_events.json()) == 1
    assert other_events.status_code == 200
    assert len(other_events.json()) == 1
    assert owner_events.json()[0]["event_id"] != other_events.json()[0]["event_id"]


def test_session_security_history_rejects_invalid_pagination(client: TestClient):
    token, _ = _register_and_login(client, "pagination")

    oversized = client.get(
        "/api/v1/auth/security-events?limit=101", headers=_headers(token)
    )
    assert oversized.status_code == 422
    assert oversized.json()["detail"]["code"] == "INVALID_SESSION_EVENT_CURSOR"

    incomplete_cursor = client.get(
        "/api/v1/auth/security-events?before_occurred_at=2026-01-01T00:00:00%2B00:00",
        headers=_headers(token),
    )
    assert incomplete_cursor.status_code == 422


def test_session_expiry_cleanup_emits_audit_event(client: TestClient):
    token, _ = _register_and_login(client, "expiry")
    state = get_app_state()
    user_id = state.identity.resolve_token(token)["id"]
    expired_token = "expired-session-audit-token"
    token_hash = hashlib.sha256(expired_token.encode("utf-8")).hexdigest()

    with state.database.transaction(immediate=True):
        state.database.connect().execute(
            """
            INSERT INTO sessions (
                token_hash, user_id, expires_at, created_at, device_id, auth_method
            ) VALUES (?, ?, ?, ?, NULL, 'account')
            """,
            (
                token_hash,
                user_id,
                "2000-01-01T00:00:00+00:00",
                "1999-12-31T00:00:00+00:00",
            ),
        )

    assert state.identity.cleanup_sessions() >= 1
    events = state.session_security_events.list_owned(user_id, limit=100)
    expired = [event for event in events if event["event_type"] == "session.expired"]
    assert len(expired) == 1
    assert expired[0]["auth_method"] == "account"


def test_session_security_events_are_immutable_and_rollback_with_session(client: TestClient):
    token, _ = _register_and_login(client, "immutable")
    state = get_app_state()
    user_id = state.identity.resolve_token(token)["id"]
    event = state.session_security_events.list_owned(user_id)[0]

    with pytest.raises(Exception, match="session security events are immutable"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE session_security_events SET event_type='session.revoked' WHERE id=?",
                (event["event_id"],),
            )

    with pytest.raises(Exception, match="may only be erased with the account"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "DELETE FROM session_security_events WHERE id=?",
                (event["event_id"],),
            )

    before = len(state.session_security_events.list_owned(user_id))
    with pytest.raises(RuntimeError, match="rollback session"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                """
                INSERT INTO sessions (
                    token_hash, user_id, expires_at, created_at, device_id, auth_method
                ) VALUES (?, ?, ?, ?, NULL, 'account')
                """,
                (
                    hashlib.sha256(b"rollback-session-token").hexdigest(),
                    user_id,
                    "2999-01-01T00:00:00+00:00",
                    "2026-11-25T00:00:00+00:00",
                ),
            )
            raise RuntimeError("rollback session")
    assert len(state.session_security_events.list_owned(user_id)) == before
