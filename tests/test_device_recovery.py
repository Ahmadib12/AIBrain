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
    old_login_challenge = client.post(
        f"/api/v1/devices/{device_id}/login/challenge"
    )
    assert old_login_challenge.status_code == 200
    old_login_data = old_login_challenge.json()
    old_login_message = base64.b64decode(
        old_login_data["message_b64"], validate=True
    )
    old_device_login = client.post(
        f"/api/v1/devices/{device_id}/login/verify",
        params={"challenge_id": old_login_data["challenge_id"]},
        json={
            "nonce": old_login_data["nonce"],
            "signature_b64": base64.b64encode(
                old_key.sign(old_login_message)
            ).decode("ascii"),
        },
    )
    assert old_device_login.status_code == 200
    old_device_token = old_device_login.json()["access_token"]

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
    old_session = client.get(
        "/api/v1/auth/me",
        headers=_headers(old_device_token),
    )
    assert old_session.status_code == 401

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

    # The database trigger enqueues a minimal notification atomically with
    # the recovery audit event; no recovery factor or key material is copied.
    queued = state.database.connect().execute(
        """
        SELECT id, event_id, recipient_email, notification_type,
               payload_json, status, attempts
        FROM security_notification_outbox WHERE event_id=(
            SELECT id FROM device_security_events
            WHERE user_id=? AND device_id=? AND event_type='device.key_rotated'
            ORDER BY occurred_at DESC LIMIT 1
        )
        """,
        (owner["id"], device_id),
    ).fetchone()
    assert queued is not None
    assert queued["recipient_email"] == email
    assert queued["notification_type"] == "device.recovery.completed"
    assert queued["status"] == "pending"
    assert queued["attempts"] == 0
    assert codes[0] not in queued["payload_json"]
    assert "fingerprint" not in queued["payload_json"]
    claimed = state.security_notifications.claim_batch(limit=5)
    assert len(claimed) == 1
    assert claimed[0]["id"] == queued["id"]
    assert claimed[0]["attempts"] == 1
    assert state.security_notifications.mark_delivered(queued["id"]) is True
    assert state.security_notifications.mark_delivered(queued["id"]) is False
    delivered = state.database.connect().execute(
        "SELECT status, delivered_at FROM security_notification_outbox WHERE id=?",
        (queued["id"],),
    ).fetchone()
    assert delivered["status"] == "delivered"
    assert delivered["delivered_at"] is not None

    # A second recovery audit event exercises the bounded retry terminal state.
    from datetime import datetime, timezone
    terminal_event_id = str(uuid4())
    with state.database.transaction():
        state.database.connect().execute(
            """
            INSERT INTO device_security_events (
                id, user_id, device_id, event_type, occurred_at, details_json
            ) VALUES (?, ?, ?, 'device.key_rotated', ?, ?)
            """,
            (
                terminal_event_id, owner["id"], device_id,
                datetime.now(timezone.utc).isoformat(), '{"recovery":true}',
            ),
        )
        state.database.connect().execute(
            "UPDATE security_notification_outbox SET attempts=7 WHERE event_id=?",
            (terminal_event_id,),
        )
    terminal_claim = state.security_notifications.claim_batch(limit=5)
    assert len(terminal_claim) == 1
    assert terminal_claim[0]["attempts"] == 8
    assert state.security_notifications.release_for_retry(
        terminal_claim[0]["id"], delay_seconds=30
    ) is True
    terminal = state.database.connect().execute(
        "SELECT status, failed_at, failure_code FROM security_notification_outbox WHERE event_id=?",
        (terminal_event_id,),
    ).fetchone()
    assert terminal["status"] == "failed"
    assert terminal["failed_at"] is not None
    assert terminal["failure_code"] == "delivery_attempts_exhausted"
    assert state.security_notifications.pending_count() == 0
    assert state.security_notifications.delivery_counts()["failed"] == 1

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


def test_one_recovery_code_cannot_authorize_two_device_rotations(client):
    email, password, token = _account(client)
    first_device, _ = _enroll_active_device(client, token)
    second_device, _ = _enroll_active_device(client, token)
    code = _issue_codes(client, token, password)[0]

    def start(device_id):
        key = Ed25519PrivateKey.generate()
        public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        response = client.post(
            f"/api/v1/devices/{device_id}/recovery/challenge",
            json={
                "email": email,
                "recovery_code": code,
                "new_public_key_b64": base64.b64encode(public_key).decode("ascii"),
            },
        )
        assert response.status_code == 200
        return key, response.json()

    first_key, first_challenge = start(first_device)
    second_key, second_challenge = start(second_device)

    def verify(device_id, key, challenge):
        message = base64.b64decode(challenge["message_b64"], validate=True)
        return client.post(
            f"/api/v1/devices/{device_id}/recovery/verify",
            params={"challenge_id": challenge["challenge_id"]},
            json={
                "nonce": challenge["nonce"],
                "new_signature_b64": base64.b64encode(key.sign(message)).decode("ascii"),
            },
        )

    assert verify(first_device, first_key, first_challenge).status_code == 200
    assert verify(second_device, second_key, second_challenge).status_code == 401


def test_recovery_code_cannot_be_used_for_another_owners_device(client):
    owner_email, owner_password, owner_token = _account(client)
    other_email, _other_password, other_token = _account(client)
    owner_device, _ = _enroll_active_device(client, owner_token)
    other_device, _ = _enroll_active_device(client, other_token)
    code = _issue_codes(client, owner_token, owner_password)[0]
    replacement = Ed25519PrivateKey.generate()
    public_key = replacement.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    response = client.post(
        f"/api/v1/devices/{other_device}/recovery/challenge",
        json={
            "email": owner_email,
            "recovery_code": code,
            "new_public_key_b64": base64.b64encode(public_key).decode("ascii"),
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "DEVICE_RECOVERY_REJECTED"


def test_notification_claims_are_multi_worker_safe_and_crash_recoverable(client):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    from backend.app.persistence.security_notifications import SecurityNotificationOutbox

    email, _password, token = _account(client)
    device_id, _key = _enroll_active_device(client, token)
    state = get_app_state()
    owner = state.identity.resolve_token(token)
    event_id = str(uuid4())
    with state.database.transaction():
        state.database.connect().execute(
            """
            INSERT INTO device_security_events (
                id, user_id, device_id, event_type, occurred_at, details_json
            ) VALUES (?, ?, ?, 'device.key_rotated', ?, ?)
            """,
            (event_id, owner["id"], device_id,
             datetime.now(timezone.utc).isoformat(), '{"recovery":true}'),
        )

    worker_a = SecurityNotificationOutbox(state.database)
    worker_b = SecurityNotificationOutbox(state.database)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda repo: repo.claim_batch(limit=1), (worker_a, worker_b)))
    claimed = [item for batch in results for item in batch]
    assert len(claimed) == 1
    notification_id = claimed[0]["id"]

    # Simulate process death after claim; an expired lease is reclaimed once.
    with state.database.transaction():
        state.database.connect().execute(
            "UPDATE security_notification_outbox SET claimed_at=? WHERE id=?",
            ("2000-01-01T00:00:00+00:00", notification_id),
        )
    recovered = worker_b.claim_batch(limit=1)
    assert len(recovered) == 1
    assert recovered[0]["id"] == notification_id
    assert recovered[0]["attempts"] == 2
    assert recovered[0]["claim_token"] != claimed[0]["claim_token"]
    assert worker_a.renew_claim(
        notification_id, claim_token=claimed[0]["claim_token"]
    ) is False
    assert worker_a.mark_delivered(
        notification_id, claim_token=claimed[0]["claim_token"]
    ) is False
    assert worker_b.mark_delivered(
        notification_id, claim_token=recovered[0]["claim_token"]
    ) is True


def test_dead_letter_redrive_is_operator_audited_and_abuse_limits_are_shared(client):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    from backend.app.persistence.security_notifications import SecurityNotificationOutbox

    email, _password, token = _account(client)
    device_id, _key = _enroll_active_device(client, token)
    state = get_app_state()
    owner = state.identity.resolve_token(token)
    event_id = str(uuid4())
    with state.database.transaction():
        state.database.connect().execute(
            """
            INSERT INTO device_security_events (
                id, user_id, device_id, event_type, occurred_at, details_json
            ) VALUES (?, ?, ?, 'device.key_rotated', ?, ?)
            """,
            (event_id, owner["id"], device_id,
             datetime.now(timezone.utc).isoformat(), '{"recovery":true}'),
        )
    row = state.database.connect().execute(
        "SELECT id FROM security_notification_outbox WHERE event_id=?", (event_id,)
    ).fetchone()
    notification_id = row["id"]
    repo = SecurityNotificationOutbox(state.database)
    claimed = repo.claim_batch(limit=1)
    assert len(claimed) == 1
    with state.database.transaction():
        state.database.connect().execute(
            "UPDATE security_notification_outbox SET attempts=8 WHERE id=?",
            (notification_id,),
        )
    # The claimed row is now at the terminal threshold.
    assert repo.release_for_retry(notification_id, delay_seconds=30) is True
    assert state.security_notification_operations.list_dead_letters(limit=10)[0]["id"] == notification_id
    assert state.security_notification_operations.redrive(
        notification_id, operator_user_id=owner["id"],
        reason="Owner confirmed this alert should be delivered again",
    ) is True
    refreshed = state.database.connect().execute(
        "SELECT status, attempts, redrive_count FROM security_notification_outbox WHERE id=?",
        (notification_id,),
    ).fetchone()
    assert dict(refreshed) == {"status": "pending", "attempts": 0, "redrive_count": 1}
    audit = state.security_notification_operations.notification_events(notification_id)
    assert len(audit) == 1
    assert audit[0]["action"] == "redrive"
    assert audit[0]["operator_user_id"] == owner["id"]
    assert audit[0]["attempts_before"] == 8
    assert audit[0]["failure_code_before"] == "delivery_attempts_exhausted"

    monitor = state.security_recovery_abuse
    with ThreadPoolExecutor(max_workers=10) as pool:
        allowed = list(pool.map(
            lambda _n: monitor.check_and_record(email, limit=5, window_seconds=300),
            range(20),
        ))
    assert sum(allowed) == 5
    assert monitor.metrics()["blocked_attempts"] == 15
    ip_limited = [
        monitor.check_and_record(
            f"ip-scope-{index}@example.com",
            source_ip="203.0.113.9",
            limit=5,
            ip_limit=3,
        )
        for index in range(5)
    ]
    assert sum(ip_limited) == 3


def test_security_notification_operator_api_requires_allowlisted_account(client, monkeypatch):
    from backend.app.auth import operator as operator_module
    from backend.app.config import Settings

    email, _password, token = _account(client)
    monkeypatch.setattr(
        operator_module, "get_settings",
        lambda: Settings(security_operator_emails=email),
    )
    response = client.get(
        "/api/v1/security-notifications/metrics",
        headers=_headers(token),
    )
    assert response.status_code == 200
    assert set(response.json()) == {"notifications", "recovery_abuse"}

    monkeypatch.setattr(
        operator_module, "get_settings",
        lambda: Settings(security_operator_emails=""),
    )
    forbidden = client.get(
        "/api/v1/security-notifications/metrics",
        headers=_headers(token),
    )
    assert forbidden.status_code == 403
