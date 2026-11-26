import base64
import hashlib
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from backend.app.app_state import get_app_state


def _account(client: TestClient):
    email = f"device-recovery-{uuid4().hex}@example.com"
    password = "safe-password-123"
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "display_name": "Recovery Test"},
    )
    assert registered.status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200
    return email, password, login.json()["access_token"]


def _headers(token: str):
    return {"Authorization": f"Bearer {token}"}


def _enroll_active_device(client: TestClient, token: str):
    old_key = Ed25519PrivateKey.generate()
    old_public = old_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = hashlib.sha256(old_public).hexdigest()
    headers = _headers(token)
    enrolled = client.post(
        "/api/v1/devices",
        headers=headers,
        json={
            "platform": "android",
            "app_version": "1.0.0",
            "display_name": "Lost phone",
            "public_key_fingerprint": fingerprint,
        },
    )
    assert enrolled.status_code == 201
    device_id = enrolled.json()["device_id"]
    registered = client.put(
        f"/api/v1/devices/{device_id}/key",
        headers=headers,
        json={"public_key_b64": base64.b64encode(old_public).decode("ascii")},
    )
    assert registered.status_code == 204

    challenge = client.post(
        f"/api/v1/devices/{device_id}/challenge",
        headers=headers,
    )
    assert challenge.status_code == 200
    proof = challenge.json()
    activated = client.post(
        f"/api/v1/devices/{device_id}/verify",
        headers=headers,
        params={"challenge_id": proof["challenge_id"]},
        json={
            "nonce": proof["nonce"],
            "signature_b64": base64.b64encode(
                old_key.sign(base64.b64decode(proof["message_b64"]))
            ).decode("ascii"),
        },
    )
    assert activated.status_code == 204
    return device_id, old_key


def _issue_codes(client: TestClient, token: str, password: str):
    response = client.post(
        "/api/v1/auth/passkeys/recovery-codes",
        headers=_headers(token),
        json={"password": password},
    )
    assert response.status_code == 200
    return response.json()["recovery_codes"]


def test_lost_device_recovery_consumes_code_and_requires_new_key_proof(client):
    email, password, token = _account(client)
    device_id, old_key = _enroll_active_device(client, token)
    state = get_app_state()
    owner = state.identity.resolve_token(token)
    codes = _issue_codes(client, token, password)
    replacement_key = Ed25519PrivateKey.generate()
    replacement_public = replacement_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    replacement_b64 = base64.b64encode(replacement_public).decode("ascii")

    challenge = client.post(
        f"/api/v1/devices/{device_id}/recovery/challenge",
        json={
            "email": email,
            "recovery_code": codes[0],
            "new_public_key_b64": replacement_b64,
        },
    )
    assert challenge.status_code == 200
    data = challenge.json()
    message = base64.b64decode(data["message_b64"], validate=True)
    assert message.startswith(b"AIBRAIN_DEVICE_KEY_RECOVERY_V1\n")
    signature = base64.b64encode(replacement_key.sign(message)).decode("ascii")

    recovered = client.post(
        f"/api/v1/devices/{device_id}/recovery/verify",
        params={"challenge_id": data["challenge_id"]},
        json={"nonce": data["nonce"], "new_signature_b64": signature},
    )
    assert recovered.status_code == 200
    assert recovered.json()["status"] == "recovered"
    assert recovered.json()["new_public_key_fingerprint"] == hashlib.sha256(
        replacement_public
    ).hexdigest()

    assert state.webauthn.count_active_recovery_codes(owner["id"]) == 9
    event = state.database.connect().execute(
        """
        SELECT details_json FROM device_security_events
        WHERE user_id=? AND device_id=? AND event_type='device.key_rotated'
        ORDER BY occurred_at DESC LIMIT 1
        """,
        (owner["id"], device_id),
    ).fetchone()
    assert event is not None
    assert '"recovery":true' in event["details_json"]

    replay = client.post(
        f"/api/v1/devices/{device_id}/recovery/verify",
        params={"challenge_id": data["challenge_id"]},
        json={"nonce": data["nonce"], "new_signature_b64": signature},
    )
    assert replay.status_code == 401

    # A passwordless device login challenge now accepts the replacement key,
    # not the lost key. A failed old-key proof does not consume the challenge.
    login_challenge = client.post(
        f"/api/v1/devices/{device_id}/login/challenge"
    )
    assert login_challenge.status_code == 200
    login_data = login_challenge.json()
    login_message = base64.b64decode(login_data["message_b64"], validate=True)
    old_attempt = client.post(
        f"/api/v1/devices/{device_id}/login/verify",
        params={"challenge_id": login_data["challenge_id"]},
        json={
            "nonce": login_data["nonce"],
            "signature_b64": base64.b64encode(old_key.sign(login_message)).decode("ascii"),
        },
    )
    assert old_attempt.status_code == 401
    new_attempt = client.post(
        f"/api/v1/devices/{device_id}/login/verify",
        params={"challenge_id": login_data["challenge_id"]},
        json={
            "nonce": login_data["nonce"],
            "signature_b64": base64.b64encode(
                replacement_key.sign(login_message)
            ).decode("ascii"),
        },
    )
    assert new_attempt.status_code == 200


def test_recovery_rejects_invalid_code_without_challenge_or_key_change(client):
    email, password, token = _account(client)
    device_id, _old_key = _enroll_active_device(client, token)
    replacement_key = Ed25519PrivateKey.generate()
    replacement_public = replacement_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    response = client.post(
        f"/api/v1/devices/{device_id}/recovery/challenge",
        json={
            "email": email,
            "recovery_code": "invalid-recovery-code-value",
            "new_public_key_b64": base64.b64encode(replacement_public).decode("ascii"),
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_RECOVERY_REJECTED"


def test_recovery_requires_replacement_private_key_and_preserves_code_on_bad_proof(client):
    email, password, token = _account(client)
    device_id, _old_key = _enroll_active_device(client, token)
    state = get_app_state()
    owner = state.identity.resolve_token(token)
    code = _issue_codes(client, token, password)[0]
    replacement_key = Ed25519PrivateKey.generate()
    replacement_public = replacement_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    challenge = client.post(
        f"/api/v1/devices/{device_id}/recovery/challenge",
        json={
            "email": email,
            "recovery_code": code,
            "new_public_key_b64": base64.b64encode(replacement_public).decode("ascii"),
        },
    )
    assert challenge.status_code == 200
    data = challenge.json()
    message = base64.b64decode(data["message_b64"], validate=True)
    attacker = Ed25519PrivateKey.generate()
    rejected = client.post(
        f"/api/v1/devices/{device_id}/recovery/verify",
        params={"challenge_id": data["challenge_id"]},
        json={
            "nonce": data["nonce"],
            "new_signature_b64": base64.b64encode(attacker.sign(message)).decode("ascii"),
        },
    )
    assert rejected.status_code == 401
    assert state.webauthn.count_active_recovery_codes(owner["id"]) == 10

    accepted = client.post(
        f"/api/v1/devices/{device_id}/recovery/verify",
        params={"challenge_id": data["challenge_id"]},
        json={
            "nonce": data["nonce"],
            "new_signature_b64": base64.b64encode(
                replacement_key.sign(message)
            ).decode("ascii"),
        },
    )
    assert accepted.status_code == 200
    assert state.webauthn.count_active_recovery_codes(owner["id"]) == 9
