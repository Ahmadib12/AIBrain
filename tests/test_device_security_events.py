
import base64
import hashlib
from uuid import uuid4

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient


def _authenticated_headers(client: TestClient) -> dict[str, str]:
    email = f"device-audit-{uuid4().hex}@example.com"
    password = "test-password-strong"
    registered = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert registered.status_code == 200
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _enroll_with_key(client: TestClient, headers: dict[str, str]):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = hashlib.sha256(public_key).hexdigest()
    response = client.post("/api/v1/devices", headers=headers, json={
        "platform": "android", "app_version": "1.0.0",
        "display_name": "Audit test phone",
        "public_key_fingerprint": fingerprint,
    })
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
    challenge = client.post(f"/api/v1/devices/{device['device_id']}/challenge", headers=headers)
    assert challenge.status_code == 200
    data = challenge.json()
    signature = private_key.sign(base64.b64decode(data["message_b64"], validate=True))
    verified = client.post(
        f"/api/v1/devices/{device['device_id']}/verify",
        params={"challenge_id": data["challenge_id"]},
        headers=headers,
        json={
            "nonce": data["nonce"],
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        },
    )
    return verified, data

def test_device_security_event_page_size_contract():
    from backend.app.persistence.device_security_events import DeviceSecurityEventRepository

    from backend.app.app_state import get_app_state
    from backend.app.persistence.device_security_events import DeviceSecurityEventRepository
    state = get_app_state()
    try:
        DeviceSecurityEventRepository(state.database).list_owned("owner", limit=101)
    except ValueError as exc:
        assert "between 1 and 100" in str(exc)
    else:
        raise AssertionError("unbounded page size accepted")

def test_device_security_history_is_owner_scoped(client):

    owner = _authenticated_headers(client)
    other = _authenticated_headers(client)
    device, key = _enroll_with_key(client, owner)
    activated, _ = _activate_with_proof(client, owner, device, key)
    assert activated.status_code == 204

    own_events = client.get("/api/v1/devices/security-events", headers=owner)
    other_events = client.get("/api/v1/devices/security-events", headers=other)
    assert own_events.status_code == 200
    assert {item["event_type"] for item in own_events.json()} >= {
        "device.enrolled", "device.key_registered", "device.activated"
    }
    assert other_events.status_code == 200
    assert other_events.json() == []


def test_device_security_history_rejects_unbounded_page_size(client):

    headers = _authenticated_headers(client)
    response = client.get("/api/v1/devices/security-events?limit=101", headers=headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EVENT_PAGE_SIZE"

def test_device_security_history_records_login_and_revocation_once(client):

    headers = _authenticated_headers(client)
    device, key = _enroll_with_key(client, headers)
    activated, _ = _activate_with_proof(client, headers, device, key)
    assert activated.status_code == 204
    challenge = client.post(f"/api/v1/devices/{device['device_id']}/login/challenge").json()
    signature = key.sign(base64.b64decode(challenge["message_b64"], validate=True))
    logged_in = client.post(
        f"/api/v1/devices/{device['device_id']}/login/verify",
        params={"challenge_id": challenge["challenge_id"]},
        json={"nonce": challenge["nonce"], "signature_b64": base64.b64encode(signature).decode("ascii")},
    )
    assert logged_in.status_code == 200

    for _ in range(2):
        revoked = client.delete(f"/api/v1/devices/{device['device_id']}", headers=headers)
        assert revoked.status_code == 200
    events = client.get("/api/v1/devices/security-events", headers=headers).json()
    kinds = [item["event_type"] for item in events]
    assert kinds.count("device.login_authenticated") == 1
    assert kinds.count("device.revoked") == 1


def test_device_security_cursor_is_stable_for_equal_timestamps(client: TestClient):
    from uuid import uuid4
    from backend.app.app_state import get_app_state

    headers = _authenticated_headers(client)
    device, key = _enroll_with_key(client, headers)
    activated, _ = _activate_with_proof(client, headers, device, key)
    assert activated.status_code == 204

    state = get_app_state()
    owner_id = client.get("/api/v1/auth/me", headers=headers).json()["user"]["id"]
    timestamp = "2999-01-01T00:00:00+00:00"
    inserted_ids = [str(uuid4()) for _ in range(3)]
    with state.database.transaction(immediate=True):
        for event_id in inserted_ids:
            state.database.connect().execute(
                """INSERT INTO device_security_events
                   (id,user_id,device_id,event_type,occurred_at,details_json)
                   VALUES (?,?,?,'device.enrolled',?,'{}')""",
                (event_id, owner_id, device["device_id"], timestamp),
            )
    first = client.get("/api/v1/devices/security-events?limit=2", headers=headers).json()
    assert len(first) == 2
    second = client.get(
        "/api/v1/devices/security-events",
        params={
            "limit": 2,
            "before_occurred_at": timestamp,
            "before_event_id": first[-1]["event_id"],
        },
        headers=headers,
    ).json()
    assert {item["event_id"] for item in first}.isdisjoint(
        {item["event_id"] for item in second}
    )
    assert len({item["event_id"] for item in first + second}) == 4
    assert set(inserted_ids).issubset(
        {item["event_id"] for item in first + second}
    )


def test_device_security_history_survives_device_removal_and_is_immutable(client: TestClient):
    headers = _authenticated_headers(client)
    device, key = _enroll_with_key(client, headers)
    activated, _ = _activate_with_proof(client, headers, device, key)
    assert activated.status_code == 204
    before = client.get("/api/v1/devices/security-events", headers=headers).json()
    assert any(item["device_id"] == device["device_id"] for item in before)

    from backend.app.app_state import get_app_state
    state = get_app_state()
    with state.database.transaction(immediate=True):
        state.database.connect().execute(
            "DELETE FROM devices WHERE id=?", (device["device_id"],)
        )
    after = client.get("/api/v1/devices/security-events", headers=headers).json()
    assert [item["event_id"] for item in after] == [item["event_id"] for item in before]
    try:
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "DELETE FROM device_security_events WHERE id=?", (after[0]["event_id"],)
            )
    except Exception as exc:
        assert "only be erased with the account" in str(exc)
    else:
        raise AssertionError("direct audit deletion was allowed")



def test_device_identity_and_registered_key_are_immutable(client: TestClient):
    from backend.app.app_state import get_app_state

    headers = _authenticated_headers(client)
    other_headers = _authenticated_headers(client)
    device, key = _enroll_with_key(client, headers)
    state = get_app_state()
    owner_id = client.get("/api/v1/auth/me", headers=headers).json()["user"]["id"]
    other_id = client.get("/api/v1/auth/me", headers=other_headers).json()["user"]["id"]
    replacement_key = base64.b64encode(b"x" * 32).decode("ascii")

    with pytest.raises(Exception, match="device key replacement requires verified rotation"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE devices SET public_key_b64=? WHERE id=?",
                (replacement_key, device["device_id"]),
            )

    with pytest.raises(Exception, match="device identity fields are immutable"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE devices SET user_id=? WHERE id=?",
                (other_id, device["device_id"]),
            )

    with pytest.raises(Exception, match="device identity fields are immutable"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE devices SET public_key_fingerprint=? WHERE id=?",
                ("0" * 64, device["device_id"]),
            )

    persisted = state.devices.get_owned(owner_id, device["device_id"])
    assert str(persisted.owner_id) == owner_id


def test_device_lifecycle_cannot_reactivate_a_revoked_device(client: TestClient):
    from backend.app.app_state import get_app_state

    headers = _authenticated_headers(client)
    device, key = _enroll_with_key(client, headers)
    activated, _ = _activate_with_proof(client, headers, device, key)
    assert activated.status_code == 204
    revoked = client.delete(f"/api/v1/devices/{device['device_id']}", headers=headers)
    assert revoked.status_code == 200

    state = get_app_state()
    with pytest.raises(Exception, match="invalid device lifecycle transition"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE devices SET status='active' WHERE id=?",
                (device["device_id"],),
            )


def test_device_audit_event_rolls_back_with_lifecycle_change(client: TestClient):
    from backend.app.app_state import get_app_state

    headers = _authenticated_headers(client)
    device, key = _enroll_with_key(client, headers)
    state = get_app_state()
    before = client.get("/api/v1/devices/security-events", headers=headers).json()

    with pytest.raises(RuntimeError, match="force rollback"):
        with state.database.transaction(immediate=True):
            state.database.connect().execute(
                "UPDATE devices SET status='active' WHERE id=?",
                (device["device_id"],),
            )
            raise RuntimeError("force rollback")

    persisted = state.devices.get_owned(
        client.get("/api/v1/auth/me", headers=headers).json()["user"]["id"],
        device["device_id"],
    )
    assert persisted.status == "pending"
    after = client.get("/api/v1/devices/security-events", headers=headers).json()
    assert [item["event_id"] for item in after] == [
        item["event_id"] for item in before
    ]
