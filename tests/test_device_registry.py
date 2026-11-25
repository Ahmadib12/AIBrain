from datetime import datetime, timezone
from uuid import uuid4

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


def test_device_enrollment_is_pending_until_explicit_confirmation(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device = _enroll(client, headers)
    assert device["status"] == "pending"

    confirmed = client.post(
        f"/api/v1/devices/{device['device_id']}/confirm",
        headers=headers,
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "active"


def test_device_records_are_owner_scoped(client: TestClient) -> None:
    owner_headers = _authenticated_headers(client)
    other_headers = _authenticated_headers(client)
    device = _enroll(client, owner_headers)

    other_list = client.get("/api/v1/devices", headers=other_headers)
    assert other_list.status_code == 200
    assert all(item["device_id"] != device["device_id"] for item in other_list.json())

    cross_owner_confirm = client.post(
        f"/api/v1/devices/{device['device_id']}/confirm",
        headers=other_headers,
    )
    assert cross_owner_confirm.status_code == 404


def test_revoked_device_cannot_report_capabilities(client: TestClient) -> None:
    headers = _authenticated_headers(client)
    device = _enroll(client, headers)
    device_id = device["device_id"]

    assert client.post(
        f"/api/v1/devices/{device_id}/confirm",
        headers=headers,
    ).status_code == 200

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
    assert report.json()["detail"]["code"] == "DEVICE_NOT_ACTIVE"


def test_device_capability_report_is_metadata_not_permission_grant(
    client: TestClient,
) -> None:
    headers = _authenticated_headers(client)
    device = _enroll(client, headers)
    device_id = device["device_id"]
    client.post(f"/api/v1/devices/{device_id}/confirm", headers=headers)

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
