import base64
import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fastapi.testclient import TestClient


def _authenticated_headers(client: TestClient) -> dict[str, str]:
    email = f"device-{uuid4().hex}@example.com"
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
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _enroll(client: TestClient, headers: dict[str, str]) -> dict:
    response = client.post(
        "/api/v1/devices",
        headers=headers,
        json={
            "platform": "android",
            "app_version": "1.0.0",
            "display_name": "My phone",
            "public_key_fingerprint": "a" * 64,
        },
    )
    assert response.status_code == 201
    return response.json()


def _enroll_with_key(client: TestClient, headers: dict[str, str]):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    fingerprint = hashlib.sha256(public_key).hexdigest()
    response = client.post(
        "/api/v1/devices",
        headers=headers,
        json={
            "platform": "android",
            "app_version": "1.0.0",
            "display_name": "My phone",
            "public_key_fingerprint": fingerprint,
        },
    )
    assert response.status_code == 201
    device = response.json()
    registered = client.put(
        f"/api/v1/devices/{device['device_id']}/key",
        headers=headers,
        json={"public_key_b64": base64.b64encode(public_key).decode("ascii")},
    )
    assert registered.status_code == 204
    return device, private_key


def _activate_with_proof(client: TestClient, headers: dict[str, str], device: dict, private_key):
    device_id = device["device_id"]
    challenge = client.post(
        f"/api/v1/devices/{device_id}/challenge", headers=headers
    )
    assert challenge.status_code == 200
    data = challenge.json()
    message = base64.b64decode(data["message_b64"], validate=True)
    signature = private_key.sign(message)
    verified = client.post(
        f"/api/v1/devices/{device_id}/verify",
        params={"challenge_id": data["challenge_id"]},
        headers=headers,
        json={
            "nonce": data["nonce"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
    )
    return verified, data


def test_device_enrollment_is_pending_until_explicit_confirmation(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    assert device["status"] == "pending"

    confirmed = client.post(
        f"/api/v1/devices/{device['device_id']}/confirm",
        headers=headers,
    )
    assert confirmed.status_code == 409
    assert confirmed.json()["error"]["code"] == "DEVICE_PROOF_REQUIRED"

    verified, _ = _activate_with_proof(client, headers, device, private_key)
    assert verified.status_code == 204

    listed = client.get("/api/v1/devices", headers=headers)
    assert listed.json()[0]["status"] == "active"



def test_device_proof_rejects_forged_signature_without_activating_device(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/challenge", headers=headers
    ).json()
    attacker_key = Ed25519PrivateKey.generate()
    forged = attacker_key.sign(
        base64.b64decode(challenge["message_b64"], validate=True)
    )
    rejected = client.post(
        f"/api/v1/devices/{device['device_id']}/verify",
        params={"challenge_id": challenge["challenge_id"]},
        headers=headers,
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(forged).decode("ascii"),
        },
    )
    assert rejected.status_code == 401
    assert rejected.json()["error"]["code"] == "DEVICE_PROOF_REJECTED"

    valid = client.post(
        f"/api/v1/devices/{device['device_id']}/verify",
        params={"challenge_id": challenge["challenge_id"]},
        headers=headers,
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(
                private_key.sign(base64.b64decode(challenge["message_b64"], validate=True))
            ).decode("ascii"),
        },
    )
    assert valid.status_code == 204


def test_device_challenge_cannot_be_replayed_after_activation(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    verified, challenge = _activate_with_proof(client, headers, device, private_key)
    assert verified.status_code == 204

    replay = client.post(
        f"/api/v1/devices/{device['device_id']}/verify",
        params={"challenge_id": challenge["challenge_id"]},
        headers=headers,
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(
                private_key.sign(base64.b64decode(challenge["message_b64"], validate=True))
            ).decode("ascii"),
        },
    )
    assert replay.status_code == 404


def test_device_public_key_must_match_enrollment_fingerprint(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device = _enroll(client, headers)
    other_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    response = client.put(
        f"/api/v1/devices/{device['device_id']}/key",
        headers=headers,
        json={"public_key_b64": base64.b64encode(other_key).decode("ascii")},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "DEVICE_KEY_REJECTED"


def test_device_records_are_owner_scoped(client: TestClient) -> None:
    owner_headers = _authenticated_headers(client)
    other_headers = _authenticated_headers(client)
    device, _private_key = _enroll_with_key(client, owner_headers)

    other_list = client.get("/api/v1/devices", headers=other_headers)
    assert other_list.status_code == 200
    assert all(item["device_id"] != device["device_id"] for item in other_list.json())

    cross_owner_challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/challenge",
        headers=other_headers,
    )
    assert cross_owner_challenge.status_code == 404


def test_revoked_device_cannot_report_capabilities(client: TestClient) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    device_id = device["device_id"]

    verified, _ = _activate_with_proof(client, headers, device, private_key)
    assert verified.status_code == 204

    revoked = client.delete(f"/api/v1/devices/{device_id}", headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revoked_at"] is not None

    report = client.put(
        f"/api/v1/devices/{device_id}/capabilities",
        headers=headers,
        json={
            "report": {
                "capabilities": ["microphone", "local_inference"],
                "reported_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    assert report.status_code == 409
    assert report.json()["error"]["code"] == "DEVICE_NOT_ACTIVE"


def test_device_capability_report_is_metadata_not_permission_grant(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    device_id = device["device_id"]
    verified, _ = _activate_with_proof(client, headers, device, private_key)
    assert verified.status_code == 204

    report = client.put(
        f"/api/v1/devices/{device_id}/capabilities",
        headers=headers,
        json={
            "report": {
                "capabilities": ["microphone"],
                "reported_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    assert report.status_code == 200
    assert report.json()["status"] == "active"


def test_device_lifecycle_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/devices")
    assert response.status_code == 401


def test_account_erasure_removes_enrolled_devices(client: TestClient) -> None:
    from backend.app.app_state import get_app_state

    headers = _authenticated_headers(client)
    device = _enroll(client, headers)
    token = headers["Authorization"].removeprefix("Bearer ")
    owner = get_app_state().identity.resolve_token(token)

    get_app_state().identity.delete_user(owner["id"])

    remaining = get_app_state().database.connect().execute(
        "SELECT id FROM devices WHERE user_id = ?",
        (owner["id"],),
    ).fetchall()
    assert remaining == []


def _create_device_session(client: TestClient, headers: dict[str, str], device: dict, private_key):
    device_id = device["device_id"]
    challenge = client.post(
        f"/api/v1/devices/{device_id}/session/challenge", headers=headers
    )
    assert challenge.status_code == 200
    data = challenge.json()
    message = base64.b64decode(data["message_b64"], validate=True)
    signature = private_key.sign(message)
    response = client.post(
        f"/api/v1/devices/{device_id}/session/verify",
        params={"challenge_id": data["challenge_id"]},
        headers=headers,
        json={
            "nonce": data["nonce"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
    )
    return response


def test_device_session_requires_active_device_proof(client: TestClient) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)

    pending_challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/session/challenge",
        headers=headers,
    )
    assert pending_challenge.status_code == 404

    activated, _ = _activate_with_proof(client, headers, device, private_key)
    assert activated.status_code == 204

    session = _create_device_session(client, headers, device, private_key)
    assert session.status_code == 200
    payload = session.json()
    assert payload["user"]["device_id"] == device["device_id"]

    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["user"]["device_id"] == device["device_id"]


def test_device_revocation_immediately_invalidates_bound_sessions(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    activated, _ = _activate_with_proof(client, headers, device, private_key)
    assert activated.status_code == 204

    session = _create_device_session(client, headers, device, private_key)
    assert session.status_code == 200
    device_token = session.json()["access_token"]
    device_headers = {"Authorization": f"Bearer {device_token}"}

    before = client.get("/api/v1/auth/me", headers=device_headers)
    assert before.status_code == 200

    revoked = client.delete(
        f"/api/v1/devices/{device['device_id']}", headers=headers
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    after = client.get("/api/v1/auth/me", headers=device_headers)
    assert after.status_code == 401

    # Revoking one device must not revoke the owner's independent account session.
    owner_session = client.get("/api/v1/auth/me", headers=headers)
    assert owner_session.status_code == 200


def test_device_session_challenge_cannot_be_replayed(client: TestClient) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    activated, _ = _activate_with_proof(client, headers, device, private_key)
    assert activated.status_code == 204

    challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/session/challenge",
        headers=headers,
    )
    assert challenge.status_code == 200
    data = challenge.json()
    signature = private_key.sign(
        base64.b64decode(data["message_b64"], validate=True)
    )
    body = {
        "nonce": data["nonce"],
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    params = {"challenge_id": data["challenge_id"]}
    first = client.post(
        f"/api/v1/devices/{device['device_id']}/session/verify",
        params=params, headers=headers, json=body,
    )
    assert first.status_code == 200
    replay = client.post(
        f"/api/v1/devices/{device['device_id']}/session/verify",
        params=params, headers=headers, json=body,
    )
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "DEVICE_SESSION_CHALLENGE_INVALID"


def test_device_session_challenge_issuance_is_rate_limited(client: TestClient) -> None:
    headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, headers)
    activated, _ = _activate_with_proof(client, headers, device, private_key)
    assert activated.status_code == 204

    for _ in range(10):
        response = client.post(
            f"/api/v1/devices/{device['device_id']}/session/challenge",
            headers=headers,
        )
        assert response.status_code == 200

    limited = client.post(
        f"/api/v1/devices/{device['device_id']}/session/challenge",
        headers=headers,
    )
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "DEVICE_CHALLENGE_RATE_LIMITED"



def _passwordless_login(client: TestClient, device: dict, private_key):
    device_id = device["device_id"]
    challenge_response = client.post(
        f"/api/v1/devices/{device_id}/login/challenge"
    )
    if challenge_response.status_code != 200:
        return challenge_response, None
    challenge = challenge_response.json()
    signature = private_key.sign(
        base64.b64decode(challenge["message_b64"], validate=True)
    )
    response = client.post(
        f"/api/v1/devices/{device_id}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
    )
    return response, challenge


def test_passwordless_device_login_needs_no_account_session(client: TestClient) -> None:
    owner_headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, private_key)
    assert activated.status_code == 204

    response, _ = _passwordless_login(client, device, private_key)
    assert response.status_code == 200
    payload = response.json()
    assert payload["user"]["device_id"] == device["device_id"]
    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["user"]["id"] == payload["user"]["id"]
    assert me.json()["user"]["device_id"] == device["device_id"]


def test_passwordless_login_rejects_unknown_pending_revoked_and_unkeyed_devices(
    client: TestClient,
) -> None:
    owner_headers = _authenticated_headers(client)
    pending, _ = _enroll_with_key(client, owner_headers)
    pending_response = client.post(
        f"/api/v1/devices/{pending['device_id']}/login/challenge"
    )
    assert pending_response.status_code == 404
    assert pending_response.json()["error"]["code"] == "DEVICE_LOGIN_UNAVAILABLE"

    unkeyed = _enroll(client, owner_headers)
    unkeyed_response = client.post(
        f"/api/v1/devices/{unkeyed['device_id']}/login/challenge"
    )
    assert unkeyed_response.status_code == 404
    assert unkeyed_response.json()["error"]["code"] == "DEVICE_LOGIN_UNAVAILABLE"

    active, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, active, private_key)
    assert activated.status_code == 204
    revoked = client.delete(
        f"/api/v1/devices/{active['device_id']}", headers=owner_headers
    )
    assert revoked.status_code == 200
    revoked_response = client.post(
        f"/api/v1/devices/{active['device_id']}/login/challenge"
    )
    assert revoked_response.status_code == 404
    assert revoked_response.json()["error"]["code"] == "DEVICE_LOGIN_UNAVAILABLE"

    unknown_response = client.post(
        f"/api/v1/devices/{uuid4()}/login/challenge"
    )
    assert unknown_response.status_code == 404
    assert unknown_response.json()["error"]["code"] == "DEVICE_LOGIN_UNAVAILABLE"


def test_passwordless_login_rejects_forgery_wrong_nonce_and_replay(
    client: TestClient,
) -> None:
    owner_headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, private_key)
    assert activated.status_code == 204

    challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/login/challenge"
    ).json()
    message = base64.b64decode(challenge["message_b64"], validate=True)
    attacker = Ed25519PrivateKey.generate()
    forged = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(attacker.sign(message)).decode("ascii"),
        },
    )
    assert forged.status_code == 401
    assert forged.json()["error"]["code"] == "DEVICE_LOGIN_REJECTED"

    wrong_nonce = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json={
            "nonce": "x" * len(challenge["nonce"]),
            "signature_b64": base64.b64encode(private_key.sign(message)).decode("ascii"),
        },
    )
    assert wrong_nonce.status_code == 401

    valid_signature = private_key.sign(message)
    body = {
        "nonce": challenge["nonce"],
        "signature_b64": base64.b64encode(valid_signature).decode("ascii"),
    }
    first = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json=body,
    )
    assert first.status_code == 200
    replay = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json=body,
    )
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "DEVICE_LOGIN_REJECTED"


def test_passwordless_login_challenge_is_rate_limited_without_authentication(
    client: TestClient,
) -> None:
    owner_headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, private_key)
    assert activated.status_code == 204

    for _ in range(10):
        response = client.post(
            f"/api/v1/devices/{device['device_id']}/login/challenge"
        )
        assert response.status_code == 200
    limited = client.post(
        f"/api/v1/devices/{device['device_id']}/login/challenge"
    )
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "DEVICE_LOGIN_RATE_LIMITED"


def test_passwordless_login_is_owner_scoped_and_revocation_is_rechecked(
    client: TestClient, monkeypatch,
) -> None:
    from backend.app.app_state import get_app_state

    owner_headers = _authenticated_headers(client)
    other_headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, private_key)
    assert activated.status_code == 204

    # A different owner's active device cannot reuse this challenge.
    other_device, other_private_key = _enroll_with_key(client, other_headers)
    other_activated, _ = _activate_with_proof(
        client, other_headers, other_device, other_private_key
    )
    assert other_activated.status_code == 204

    challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/login/challenge"
    ).json()
    message = base64.b64decode(challenge["message_b64"], validate=True)
    signature = private_key.sign(message)
    cross_owner = client.post(
        f"/api/v1/devices/{other_device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
    )
    assert cross_owner.status_code == 401

    state = get_app_state()
    original_create_session = state.identity.create_session

    def revoke_before_session(
        user_id: str,
        *,
        device_id: str | None = None,
        auth_method: str | None = None,
    ):
        state.devices.revoke(user_id, device_id)
        return original_create_session(
            user_id, device_id=device_id, auth_method=auth_method
        )

    monkeypatch.setattr(state.identity, "create_session", revoke_before_session)
    response = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_LOGIN_REJECTED"



def test_passwordless_device_login_rejects_expired_challenge(client: TestClient) -> None:
    from backend.app.app_state import get_app_state

    owner_headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, private_key)
    assert activated.status_code == 204

    challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/login/challenge"
    ).json()
    state = get_app_state()
    with state.database.transaction(immediate=True):
        state.database.connect().execute(
            "UPDATE device_auth_challenges SET expires_at=? WHERE id=?",
            ("2000-01-01T00:00:00+00:00", challenge["challenge_id"]),
        )
    signature = private_key.sign(
        base64.b64decode(challenge["message_b64"], validate=True)
    )
    response = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json={
            "nonce": challenge["nonce"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_LOGIN_REJECTED"



def test_session_device_binding_and_authentication_provenance_are_immutable(
    client: TestClient,
) -> None:
    import pytest
    from backend.app.app_state import get_app_state

    owner_headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, private_key)
    assert activated.status_code == 204
    session = _create_device_session(client, owner_headers, device, private_key)
    assert session.status_code == 200

    token = session.json()["access_token"]
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    state = get_app_state()
    row = state.database.connect().execute(
        "SELECT * FROM sessions WHERE token_hash=?", (token_hash,)
    ).fetchone()
    assert row["device_id"] == device["device_id"]
    assert row["auth_method"] == "device_proof"

    for sql, values in (
        ("UPDATE sessions SET device_id=NULL WHERE token_hash=?", (token_hash,)),
        ("UPDATE sessions SET auth_method='account' WHERE token_hash=?", (token_hash,)),
        ("UPDATE sessions SET expires_at='2999-01-01T00:00:00+00:00' WHERE token_hash=?", (token_hash,)),
        ("UPDATE sessions SET token_hash=? WHERE token_hash=?", ("f" * 64, token_hash)),
    ):
        with pytest.raises(Exception, match="session identity and authentication binding are immutable"):
            with state.database.transaction(immediate=True):
                state.database.connect().execute(sql, values)


def test_database_rejects_sessions_with_invalid_device_authentication_binding(
    client: TestClient,
) -> None:
    import pytest
    from datetime import timedelta
    from backend.app.app_state import get_app_state

    owner_headers = _authenticated_headers(client)
    device, private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, private_key)
    assert activated.status_code == 204

    state = get_app_state()
    user_id = state.identity.resolve_token(
        owner_headers["Authorization"].removeprefix("Bearer ")
    )["id"]
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(hours=1)).isoformat()

    with pytest.raises(Exception, match="session authentication method and device binding are inconsistent"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                """INSERT INTO sessions
                   (token_hash,user_id,expires_at,created_at,device_id,auth_method)
                   VALUES (?,?,?,?,?,'account')""",
                ("a" * 64, user_id, expires, now.isoformat(), device["device_id"]),
            )

    with pytest.raises(Exception, match="session authentication method and device binding are inconsistent"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                """INSERT INTO sessions
                   (token_hash,user_id,expires_at,created_at,device_id,auth_method)
                   VALUES (?,?,?, ?,NULL,'device_login')""",
                ("b" * 64, user_id, expires, now.isoformat()),
            )


def test_session_revocation_cannot_be_reversed(client: TestClient) -> None:
    import pytest
    from backend.app.app_state import get_app_state

    headers = _authenticated_headers(client)
    token = headers["Authorization"].removeprefix("Bearer ")
    state = get_app_state()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert state.identity.revoke_token(token)

    with pytest.raises(Exception, match="session revocation is irreversible"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE sessions SET revoked_at=NULL WHERE token_hash=?",
                (token_hash,),
            )\n

def test_device_key_rotation_requires_both_keys_and_revokes_old_sessions(
    client: TestClient,
) -> None:
    from backend.app.app_state import get_app_state

    owner_headers = _authenticated_headers(client)
    device, old_private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, old_private_key)
    assert activated.status_code == 204

    old_session = _create_device_session(
        client, owner_headers, device, old_private_key
    )
    assert old_session.status_code == 200
    old_token = old_session.json()["access_token"]
    old_headers = {"Authorization": f"Bearer {old_token}"}

    new_private_key = Ed25519PrivateKey.generate()
    new_public_key = new_private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    new_public_key_b64 = base64.b64encode(new_public_key).decode("ascii")
    challenge_response = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/challenge",
        headers=owner_headers,
        json={"new_public_key_b64": new_public_key_b64},
    )
    assert challenge_response.status_code == 200
    challenge = challenge_response.json()
    message = base64.b64decode(challenge["message_b64"], validate=True)

    # Possession of only the replacement key is insufficient.
    attacker = Ed25519PrivateKey.generate()
    rejected = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/verify",
        params={"challenge_id": challenge["challenge_id"]},
        headers=owner_headers,
        json={
            "nonce": challenge["nonce"],
            "old_signature_b64": base64.b64encode(attacker.sign(message)).decode("ascii"),
            "new_signature_b64": base64.b64encode(new_private_key.sign(message)).decode("ascii"),
        },
    )
    assert rejected.status_code == 401
    assert rejected.json()["error"]["code"] == "DEVICE_KEY_ROTATION_PROOF_REJECTED"
    assert client.get("/api/v1/auth/me", headers=old_headers).status_code == 200

    forged_replacement = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/verify",
        params={"challenge_id": challenge["challenge_id"]},
        headers=owner_headers,
        json={
            "nonce": challenge["nonce"],
            "old_signature_b64": base64.b64encode(old_private_key.sign(message)).decode("ascii"),
            "new_signature_b64": base64.b64encode(attacker.sign(message)).decode("ascii"),
        },
    )
    assert forged_replacement.status_code == 401
    assert client.get("/api/v1/auth/me", headers=old_headers).status_code == 200

    rotated = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/verify",
        params={"challenge_id": challenge["challenge_id"]},
        headers=owner_headers,
        json={
            "nonce": challenge["nonce"],
            "old_signature_b64": base64.b64encode(old_private_key.sign(message)).decode("ascii"),
            "new_signature_b64": base64.b64encode(new_private_key.sign(message)).decode("ascii"),
        },
    )
    assert rotated.status_code == 200
    assert rotated.json()["status"] == "rotated"
    assert rotated.json()["public_key_fingerprint"] == challenge["new_public_key_fingerprint"]

    # Rotation invalidates every old device-bound session.
    assert client.get("/api/v1/auth/me", headers=old_headers).status_code == 401
    state = get_app_state()
    stored = state.devices.get_owned(
        state.identity.resolve_token(
            owner_headers["Authorization"].removeprefix("Bearer ")
        )["id"],
        device["device_id"],
    )
    assert stored.public_key_fingerprint == challenge["new_public_key_fingerprint"]

    events = client.get("/api/v1/devices/security-events", headers=owner_headers)
    assert events.status_code == 200
    rotations = [
        event for event in events.json()
        if event["device_id"] == device["device_id"]
        and event["event_type"] == "device.key_rotated"
    ]
    assert len(rotations) == 1
    assert rotations[0]["details"]["previous_fingerprint"] == device["public_key_fingerprint"]
    assert rotations[0]["details"]["new_fingerprint"] == challenge["new_public_key_fingerprint"]

    # The new key can authenticate; the old key cannot.
    new_challenge = client.post(
        f"/api/v1/devices/{device['device_id']}/login/challenge"
    )
    assert new_challenge.status_code == 200
    login_data = new_challenge.json()
    login_message = base64.b64decode(login_data["message_b64"], validate=True)
    old_login = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": login_data["challenge_id"]},
        json={
            "nonce": login_data["nonce"],
            "signature_b64": base64.b64encode(old_private_key.sign(login_message)).decode("ascii"),
        },
    )
    assert old_login.status_code == 401
    new_login = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": login_data["challenge_id"]},
        json={
            "nonce": login_data["nonce"],
            "signature_b64": base64.b64encode(new_private_key.sign(login_message)).decode("ascii"),
        },
    )
    assert new_login.status_code == 200

    replay = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/verify",
        params={"challenge_id": challenge["challenge_id"]},
        headers=owner_headers,
        json={
            "nonce": challenge["nonce"],
            "old_signature_b64": base64.b64encode(old_private_key.sign(message)).decode("ascii"),
            "new_signature_b64": base64.b64encode(new_private_key.sign(message)).decode("ascii"),
        },
    )
    assert replay.status_code == 409


def test_device_key_rotation_is_owner_scoped_and_requires_an_active_device(
    client: TestClient,
) -> None:
    owner_headers = _authenticated_headers(client)
    other_headers = _authenticated_headers(client)
    device, old_private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, old_private_key)
    assert activated.status_code == 204
    replacement = Ed25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    body = {"new_public_key_b64": base64.b64encode(replacement).decode("ascii")}

    cross_owner = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/challenge",
        headers=other_headers,
        json=body,
    )
    assert cross_owner.status_code == 404

    revoked = client.delete(
        f"/api/v1/devices/{device['device_id']}", headers=owner_headers
    )
    assert revoked.status_code == 200
    inactive = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/challenge",
        headers=owner_headers,
        json=body,
    )
    assert inactive.status_code == 404


def test_device_key_rotation_rejects_direct_key_mutation(client: TestClient) -> None:
    import pytest
    from backend.app.app_state import get_app_state

    owner_headers = _authenticated_headers(client)
    device, old_private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, old_private_key)
    assert activated.status_code == 204

    state = get_app_state()
    with pytest.raises(Exception, match="device key replacement requires verified rotation"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE devices SET public_key_fingerprint=? WHERE id=?",
                ("b" * 64, device["device_id"]),
            )\n

def test_device_key_rotation_rejects_challenge_bound_to_previous_key_version(
    client: TestClient,
) -> None:
    owner_headers = _authenticated_headers(client)
    device, old_private_key = _enroll_with_key(client, owner_headers)
    activated, _ = _activate_with_proof(client, owner_headers, device, old_private_key)
    assert activated.status_code == 204

    replacement_a = Ed25519PrivateKey.generate()
    replacement_b = Ed25519PrivateKey.generate()
    public_a = replacement_a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_b = replacement_b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def issue(public_key: bytes) -> dict:
        response = client.post(
            f"/api/v1/devices/{device['device_id']}/key-rotation/challenge",
            headers=owner_headers,
            json={"new_public_key_b64": base64.b64encode(public_key).decode("ascii")},
        )
        assert response.status_code == 200
        return response.json()

    first = issue(public_a)
    stale = issue(public_b)

    first_message = base64.b64decode(first["message_b64"], validate=True)
    first_rotation = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/verify",
        params={"challenge_id": first["challenge_id"]},
        headers=owner_headers,
        json={
            "nonce": first["nonce"],
            "old_signature_b64": base64.b64encode(old_private_key.sign(first_message)).decode("ascii"),
            "new_signature_b64": base64.b64encode(replacement_a.sign(first_message)).decode("ascii"),
        },
    )
    assert first_rotation.status_code == 200

    stale_message = base64.b64decode(stale["message_b64"], validate=True)
    stale_rotation = client.post(
        f"/api/v1/devices/{device['device_id']}/key-rotation/verify",
        params={"challenge_id": stale["challenge_id"]},
        headers=owner_headers,
        json={
            "nonce": stale["nonce"],
            "old_signature_b64": base64.b64encode(replacement_a.sign(stale_message)).decode("ascii"),
            "new_signature_b64": base64.b64encode(replacement_b.sign(stale_message)).decode("ascii"),
        },
    )
    assert stale_rotation.status_code == 409
    assert stale_rotation.json()["error"]["code"] == "DEVICE_KEY_ROTATION_CHALLENGE_INVALID"
