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


def test_device_records_are_owner_scoped(client: TestClient) -> None:
    owner_headers = _authenticated_headers(client)
    other_headers = _authenticated_headers(client)
    device = _enroll(client, owner_headers)

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
