def test_device_security_event_page_size_contract():
    from backend.app.persistence.device_security_events import DeviceSecurityEventRepository

    try:
        DeviceSecurityEventRepository.list_owned(None, "owner", limit=101)
    except ValueError as exc:
        assert "between 1 and 100" in str(exc)
    else:
        raise AssertionError("unbounded page size accepted")

def test_device_security_history_is_owner_scoped(client):
    from test_device_registry import _authenticated_headers, _enroll_with_key, _activate_with_proof

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
    from test_device_registry import _authenticated_headers

    headers = _authenticated_headers(client)
    response = client.get("/api/v1/devices/security-events?limit=101", headers=headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EVENT_PAGE_SIZE"

def test_device_security_history_records_login_and_revocation_once(client):
    import base64
    from test_device_registry import _authenticated_headers, _enroll_with_key, _activate_with_proof

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
