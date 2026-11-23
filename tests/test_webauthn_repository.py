import sqlite3
import uuid

import pytest

from backend.app.persistence.database import Database


def create_database(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'webauthn.db'}")
    with database.transaction():
        connection = database.connect()
        user_id = str(uuid.uuid4())
        connection.execute(
            """
            INSERT INTO users (
                id, email, password_salt, password_hash,
                display_name, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                f"{user_id}@example.com",
                "test-password-salt",
                "test-password-hash",
                "Test User",
                "2026-01-01T00:00:00+00:00",
            ),
        )
    return database, user_id


def test_repository_module_exports_webauthn_repository():
    from backend.app.persistence import webauthn

    assert hasattr(webauthn, "WebAuthnRepository")


def test_create_credential_stores_public_key_and_metadata(tmp_path):
    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    credential = repository.create_credential(
        user_id=user_id,
        credential_id="credential-001",
        public_key=b"test-public-key",
        sign_count=3,
        transports=("internal", "usb"),
        device_type="single_device",
        backed_up=False,
        name="My Passkey",
    )

    assert credential["user_id"] == user_id
    assert credential["credential_id"] == "credential-001"
    assert credential["public_key"] == b"test-public-key"
    assert credential["sign_count"] == 3
    assert credential["transports"] == ["internal", "usb"]
    assert credential["device_type"] == "single_device"
    assert credential["backed_up"] is False
    assert credential["name"] == "My Passkey"
    assert credential["revoked_at"] is None


def test_credential_is_retrievable_by_owner(tmp_path):
    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    created = repository.create_credential(
        user_id=user_id,
        credential_id="credential-002",
        public_key=b"public-key",
    )

    retrieved = repository.get_credential(user_id, created["id"])

    assert retrieved is not None
    assert retrieved["id"] == created["id"]
    assert retrieved["credential_id"] == "credential-002"


def test_credential_is_not_visible_to_another_user(tmp_path):
    database, user_id = create_database(tmp_path)
    _, other_user_id = create_database(tmp_path / "other")

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    created = repository.create_credential(
        user_id=user_id,
        credential_id="credential-003",
        public_key=b"public-key",
    )

    assert repository.get_credential(other_user_id, created["id"]) is None


def test_duplicate_credential_id_is_rejected(tmp_path):
    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    repository.create_credential(
        user_id=user_id,
        credential_id="credential-004",
        public_key=b"public-key-1",
    )

    with pytest.raises(sqlite3.IntegrityError):
        repository.create_credential(
            user_id=user_id,
            credential_id="credential-004",
            public_key=b"public-key-2",
        )


def test_list_credentials_excludes_revoked_by_default(tmp_path):
    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    first = repository.create_credential(
        user_id=user_id,
        credential_id="credential-005",
        public_key=b"key-1",
    )
    second = repository.create_credential(
        user_id=user_id,
        credential_id="credential-006",
        public_key=b"key-2",
    )

    repository.revoke_credential(user_id, first["id"])

    active = repository.list_credentials(user_id)
    all_credentials = repository.list_credentials(
        user_id,
        include_revoked=True,
    )

    assert [item["id"] for item in active] == [second["id"]]
    assert len(all_credentials) == 2


def test_revoke_credential_is_owner_scoped(tmp_path):
    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    created = repository.create_credential(
        user_id=user_id,
        credential_id="credential-007",
        public_key=b"public-key",
    )

    _, other_user_id = create_database(tmp_path / "other")

    with pytest.raises(LookupError):
        repository.revoke_credential(other_user_id, created["id"])

    assert repository.get_credential(user_id, created["id"])["revoked_at"] is None


def test_create_challenge_stores_hash_and_metadata(tmp_path):
    import hashlib
    from datetime import datetime, timedelta, timezone

    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    raw_challenge = b"random-registration-challenge"
    challenge_hash = hashlib.sha256(raw_challenge).hexdigest()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat()

    challenge = repository.create_challenge(
        user_id=user_id,
        challenge_hash=challenge_hash,
        purpose="registration",
        expires_at=expires_at,
    )

    assert challenge["user_id"] == user_id
    assert challenge["challenge_hash"] == challenge_hash
    assert challenge["purpose"] == "registration"
    assert challenge["expires_at"] == expires_at
    assert challenge["consumed_at"] is None
    assert "challenge" not in challenge


def test_challenge_is_owner_scoped(tmp_path):
    import hashlib
    from datetime import datetime, timedelta, timezone

    database, user_id = create_database(tmp_path)
    _, other_user_id = create_database(tmp_path / "other")

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat()

    created = repository.create_challenge(
        user_id=user_id,
        challenge_hash=hashlib.sha256(b"owner-test").hexdigest(),
        purpose="authentication",
        expires_at=expires_at,
    )

    assert repository.get_challenge(
        other_user_id, created["id"]
    ) is None


def test_challenge_can_only_be_consumed_once(tmp_path):
    import hashlib
    from datetime import datetime, timedelta, timezone

    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat()

    created = repository.create_challenge(
        user_id=user_id,
        challenge_hash=hashlib.sha256(b"single-use").hexdigest(),
        purpose="authentication",
        expires_at=expires_at,
    )

    consumed = repository.consume_challenge(user_id, created["id"])

    assert consumed is not None
    assert consumed["consumed_at"] is not None

    assert repository.consume_challenge(user_id, created["id"]) is None


def test_expired_challenge_cannot_be_consumed(tmp_path):
    import hashlib
    from datetime import datetime, timedelta, timezone

    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat()

    created = repository.create_challenge(
        user_id=user_id,
        challenge_hash=hashlib.sha256(b"expired").hexdigest(),
        purpose="registration",
        expires_at=expires_at,
    )

    expired_at = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()

    with database.transaction(immediate=True):
        database.connect().execute(
            """
            UPDATE webauthn_challenges
            SET expires_at = ?
            WHERE id = ?
            """,
            (expired_at, created["id"]),
        )

    assert repository.consume_challenge(user_id, created["id"]) is None


def test_challenge_rejects_invalid_purpose_and_hash(tmp_path):
    from datetime import datetime, timedelta, timezone

    database, user_id = create_database(tmp_path)

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat()

    with pytest.raises(ValueError):
        repository.create_challenge(
            user_id=user_id,
            challenge_hash=__import__("hashlib").sha256(b"valid-purpose-test").hexdigest(),
            purpose="unknown",
            expires_at=expires_at,
        )

    with pytest.raises(ValueError):
        repository.create_challenge(
            user_id=user_id,
            challenge_hash="not-a-sha256-hash",
            purpose="registration",
            expires_at=expires_at,
        )


def create_tool_approval_fixture(
    tmp_path,
    *,
    initial_sign_count=0,
    challenge_request_id=None,
    challenge_digest=None,
    challenge_fingerprint=None,
    request_expiry_state="future",
):
    import hashlib
    from datetime import datetime, timedelta, timezone

    from backend.app.persistence.tool_requests import (
        ToolRequestRepository,
        _request_digest,
    )
    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    webauthn = WebAuthnRepository(database)
    requests = ToolRequestRepository(database)

    fingerprint = "a" * 64
    request = requests.create(
        user_id,
        tool_id="test-state-change",
        arguments={"value": "original"},
        status="pending",
        expires_at=(
            (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
            if request_expiry_state == "future"
            else None
            if request_expiry_state == "missing"
            else "not-a-valid-timestamp"
            if request_expiry_state == "malformed"
            else (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            if request_expiry_state == "expired"
            else (_ for _ in ()).throw(
                ValueError("Unknown request_expiry_state")
            )
        ),
        contract_fingerprint=fingerprint,
        authorization_policy="passkey",
    )

    digest = _request_digest(
        "test-state-change",
        {"value": "original"},
        fingerprint,
    )

    credential = webauthn.create_credential(
        user_id=user_id,
        credential_id=f"credential-{uuid.uuid4()}",
        public_key=b"test-public-key",
        sign_count=initial_sign_count,
    )

    bound_request_id = request["id"]
    if challenge_request_id is not None:
        other_request = requests.create(
            user_id,
            tool_id="another-state-change",
            arguments={"value": "another"},
            status="pending",
            contract_fingerprint=fingerprint,
            authorization_policy="passkey",
        )
        bound_request_id = other_request["id"]

    challenge = webauthn.create_challenge(
        user_id=user_id,
        challenge_hash=hashlib.sha256(
            f"challenge-{uuid.uuid4()}".encode()
        ).hexdigest(),
        purpose="tool_approval",
        request_id=bound_request_id,
        proposal_digest=challenge_digest or digest,
        contract_fingerprint=challenge_fingerprint or fingerprint,
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
    )

    return {
        "database": database,
        "user_id": user_id,
        "webauthn": webauthn,
        "requests": requests,
        "request": request,
        "credential": credential,
        "challenge": challenge,
        "digest": digest,
        "fingerprint": fingerprint,
    }


def assert_authorization_state_unchanged(fixture):
    connection = fixture["database"].connect()

    challenge = connection.execute(
        "SELECT consumed_at FROM webauthn_challenges WHERE id = ?",
        (fixture["challenge"]["id"],),
    ).fetchone()

    credential = connection.execute(
        "SELECT sign_count, last_used_at FROM webauthn_credentials WHERE id = ?",
        (fixture["credential"]["id"],),
    ).fetchone()

    request = connection.execute(
        "SELECT status, consumed_at FROM tool_requests WHERE id = ?",
        (fixture["request"]["id"],),
    ).fetchone()

    authorization = connection.execute(
        "SELECT 1 FROM tool_authorizations WHERE request_id = ?",
        (fixture["request"]["id"],),
    ).fetchone()

    assert challenge["consumed_at"] is None
    assert credential["sign_count"] == fixture["credential"]["sign_count"]
    assert credential["last_used_at"] is None
    assert request["status"] == "pending"
    assert request["consumed_at"] is None
    assert authorization is None


def test_verified_tool_authorization_commits_all_state_atomically(
    tmp_path,
):
    fixture = create_tool_approval_fixture(tmp_path)

    result = fixture["webauthn"].commit_verified_tool_authorization(
        user_id=fixture["user_id"],
        request_id=fixture["request"]["id"],
        challenge_record_id=fixture["challenge"]["id"],
        credential_record_id=fixture["credential"]["id"],
        verified_sign_count=1,
    )

    connection = fixture["database"].connect()

    request = connection.execute(
        "SELECT status, consumed_at FROM tool_requests WHERE id = ?",
        (fixture["request"]["id"],),
    ).fetchone()

    challenge = connection.execute(
        "SELECT consumed_at FROM webauthn_challenges WHERE id = ?",
        (fixture["challenge"]["id"],),
    ).fetchone()

    credential = connection.execute(
        "SELECT sign_count, last_used_at FROM webauthn_credentials WHERE id = ?",
        (fixture["credential"]["id"],),
    ).fetchone()

    authorization = connection.execute(
        "SELECT * FROM tool_authorizations WHERE request_id = ?",
        (fixture["request"]["id"],),
    ).fetchone()

    assert result is not None
    assert request["status"] == "executing"
    assert request["consumed_at"] is not None
    assert challenge["consumed_at"] is not None
    assert credential["sign_count"] == 1
    assert credential["last_used_at"] is not None
    assert authorization is not None
    assert authorization["user_id"] == fixture["user_id"]
    assert authorization["challenge_id"] == fixture["challenge"]["id"]
    assert authorization["credential_id"] == fixture["credential"]["id"]
    assert authorization["proposal_digest"] == fixture["digest"]
    assert authorization["contract_fingerprint"] == fixture["fingerprint"]


def test_tool_authorization_rejects_challenge_bound_to_another_request(
    tmp_path,
):
    fixture = create_tool_approval_fixture(
        tmp_path,
        challenge_request_id="another-request",
    )

    with pytest.raises(PermissionError):
        fixture["webauthn"].commit_verified_tool_authorization(
            user_id=fixture["user_id"],
            request_id=fixture["request"]["id"],
            challenge_record_id=fixture["challenge"]["id"],
            credential_record_id=fixture["credential"]["id"],
            verified_sign_count=1,
        )

    assert_authorization_state_unchanged(fixture)


def test_tool_authorization_rejects_revoked_credential(tmp_path):
    fixture = create_tool_approval_fixture(tmp_path)

    fixture["webauthn"].revoke_credential(
        fixture["user_id"],
        fixture["credential"]["id"],
    )

    with pytest.raises(PermissionError):
        fixture["webauthn"].commit_verified_tool_authorization(
            user_id=fixture["user_id"],
            request_id=fixture["request"]["id"],
            challenge_record_id=fixture["challenge"]["id"],
            credential_record_id=fixture["credential"]["id"],
            verified_sign_count=1,
        )

    assert_authorization_state_unchanged(fixture)


def test_tool_authorization_rejects_signature_counter_rollback(tmp_path):
    fixture = create_tool_approval_fixture(
        tmp_path,
        initial_sign_count=8,
    )

    with pytest.raises(PermissionError):
        fixture["webauthn"].commit_verified_tool_authorization(
            user_id=fixture["user_id"],
            request_id=fixture["request"]["id"],
            challenge_record_id=fixture["challenge"]["id"],
            credential_record_id=fixture["credential"]["id"],
            verified_sign_count=7,
        )

    assert_authorization_state_unchanged(fixture)


def test_tool_authorization_rejects_request_tampering(tmp_path):
    fixture = create_tool_approval_fixture(tmp_path)

    with fixture["database"].transaction(immediate=True):
        fixture["database"].connect().execute(
            """
            UPDATE tool_requests
            SET arguments_json = ?
            WHERE id = ?
            """,
            ('{"value":"tampered"}', fixture["request"]["id"]),
        )

    with pytest.raises(PermissionError):
        fixture["webauthn"].commit_verified_tool_authorization(
            user_id=fixture["user_id"],
            request_id=fixture["request"]["id"],
            challenge_record_id=fixture["challenge"]["id"],
            credential_record_id=fixture["credential"]["id"],
            verified_sign_count=1,
        )

    assert_authorization_state_unchanged(fixture)

@pytest.mark.parametrize(
    "expiry_state",
    ["missing", "malformed", "expired"],
)
def test_tool_authorization_rejects_invalid_request_expiry(
    tmp_path,
    expiry_state,
):
    fixture = create_tool_approval_fixture(
        tmp_path,
        request_expiry_state=expiry_state,
    )

    with pytest.raises(PermissionError):
        fixture["webauthn"].commit_verified_tool_authorization(
            user_id=fixture["user_id"],
            request_id=fixture["request"]["id"],
            challenge_record_id=fixture["challenge"]["id"],
            credential_record_id=fixture["credential"]["id"],
            verified_sign_count=1,
        )

    assert_authorization_state_unchanged(fixture)


def test_tool_authorization_rejects_non_passkey_policy_without_consuming_state(
    tmp_path,
):
    fixture = create_tool_approval_fixture(tmp_path)

    with fixture["database"].transaction(immediate=True):
        fixture["database"].connect().execute(
            """
            UPDATE tool_requests
            SET authorization_policy = 'read_only'
            WHERE id = ?
            """,
            (fixture["request"]["id"],),
        )

    with pytest.raises(
        PermissionError,
        match="not authorized for passkey approval",
    ):
        fixture["webauthn"].commit_verified_tool_authorization(
            user_id=fixture["user_id"],
            request_id=fixture["request"]["id"],
            challenge_record_id=fixture["challenge"]["id"],
            credential_record_id=fixture["credential"]["id"],
            verified_sign_count=1,
        )

    assert_authorization_state_unchanged(fixture)

def create_registration_challenge(database, user_id, purpose="registration"):
    import hashlib
    from datetime import datetime, timedelta, timezone

    from backend.app.persistence.webauthn import WebAuthnRepository

    repository = WebAuthnRepository(database)
    challenge_hash = hashlib.sha256(
        str(uuid.uuid4()).encode()
    ).hexdigest()

    return repository.create_challenge(
        user_id=user_id,
        challenge_hash=challenge_hash,
        purpose=purpose,
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
    )


def test_verified_registration_commits_credential_and_challenge_atomically(
    tmp_path,
):
    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    repository = WebAuthnRepository(database)
    challenge = create_registration_challenge(database, user_id)

    credential = repository.commit_verified_registration(
        user_id=user_id,
        challenge_record_id=challenge["id"],
        credential_id="registration-credential-001",
        public_key=b"verified-public-key",
        sign_count=2,
        transports=("internal", "hybrid"),
        device_type="multi_device",
        backed_up=True,
        name="My Passkey",
    )

    stored_challenge = repository.get_challenge(user_id, challenge["id"])

    assert credential["user_id"] == user_id
    assert credential["credential_id"] == "registration-credential-001"
    assert credential["public_key"] == b"verified-public-key"
    assert credential["sign_count"] == 2
    assert credential["transports"] == ["internal", "hybrid"]
    assert credential["device_type"] == "multi_device"
    assert credential["backed_up"] is True
    assert credential["name"] == "My Passkey"
    assert stored_challenge["consumed_at"] is not None


def test_verified_registration_challenge_cannot_be_replayed(tmp_path):
    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    repository = WebAuthnRepository(database)
    challenge = create_registration_challenge(database, user_id)

    arguments = {
        "user_id": user_id,
        "challenge_record_id": challenge["id"],
        "credential_id": "registration-replay-credential",
        "public_key": b"verified-public-key",
    }

    repository.commit_verified_registration(**arguments)

    with pytest.raises(PermissionError):
        repository.commit_verified_registration(
            **{
                **arguments,
                "credential_id": "registration-replay-second-credential",
            }
        )

    assert len(repository.list_credentials(user_id)) == 1


def test_verified_registration_rejects_wrong_challenge_purpose(tmp_path):
    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    repository = WebAuthnRepository(database)
    challenge = create_registration_challenge(
        database,
        user_id,
        purpose="authentication",
    )

    with pytest.raises(PermissionError):
        repository.commit_verified_registration(
            user_id=user_id,
            challenge_record_id=challenge["id"],
            credential_id="wrong-purpose-credential",
            public_key=b"verified-public-key",
        )

    assert repository.list_credentials(user_id) == []
    assert repository.get_challenge(user_id, challenge["id"])["consumed_at"] is None


def test_verified_registration_rejects_expired_challenge(tmp_path):
    from datetime import datetime, timedelta, timezone

    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    repository = WebAuthnRepository(database)
    challenge = create_registration_challenge(database, user_id)

    expired_at = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()

    with database.transaction(immediate=True):
        database.connect().execute(
            """
            UPDATE webauthn_challenges
            SET expires_at = ?
            WHERE id = ?
            """,
            (expired_at, challenge["id"]),
        )

    with pytest.raises(PermissionError):
        repository.commit_verified_registration(
            user_id=user_id,
            challenge_record_id=challenge["id"],
            credential_id="expired-registration-credential",
            public_key=b"verified-public-key",
        )

    assert repository.list_credentials(user_id) == []
    assert repository.get_challenge(user_id, challenge["id"])["consumed_at"] is None


def test_verified_registration_challenge_is_owner_scoped(tmp_path):
    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    repository = WebAuthnRepository(database)
    challenge = create_registration_challenge(database, user_id)

    other_user_id = str(uuid.uuid4())
    with database.transaction():
        database.connect().execute(
            """
            INSERT INTO users (
                id, email, password_salt, password_hash,
                display_name, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                other_user_id,
                f"{other_user_id}@example.com",
                "test-password-salt",
                "test-password-hash",
                "Other User",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    with pytest.raises(LookupError):
        repository.commit_verified_registration(
            user_id=other_user_id,
            challenge_record_id=challenge["id"],
            credential_id="cross-account-registration-credential",
            public_key=b"verified-public-key",
        )

    assert repository.list_credentials(user_id) == []
    assert repository.list_credentials(other_user_id) == []
    assert repository.get_challenge(user_id, challenge["id"])["consumed_at"] is None


def test_verified_registration_rejects_globally_duplicate_credential_id(
    tmp_path,
):
    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    repository = WebAuthnRepository(database)

    repository.create_credential(
        user_id=user_id,
        credential_id="globally-duplicate-registration-id",
        public_key=b"existing-public-key",
    )
    challenge = create_registration_challenge(database, user_id)

    with pytest.raises(sqlite3.IntegrityError):
        repository.commit_verified_registration(
            user_id=user_id,
            challenge_record_id=challenge["id"],
            credential_id="globally-duplicate-registration-id",
            public_key=b"new-public-key",
        )

    assert len(repository.list_credentials(user_id)) == 1
    assert repository.get_challenge(user_id, challenge["id"])["consumed_at"] is None


def test_verified_registration_rolls_back_credential_if_challenge_consumption_fails(
    tmp_path,
):
    from backend.app.persistence.webauthn import WebAuthnRepository

    database, user_id = create_database(tmp_path)
    repository = WebAuthnRepository(database)
    challenge = create_registration_challenge(database, user_id)

    with database.transaction():
        database.connect().execute(
            """
            CREATE TRIGGER fail_registration_challenge_consumption
            BEFORE UPDATE OF consumed_at ON webauthn_challenges
            WHEN NEW.consumed_at IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'forced challenge consumption failure');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError):
        repository.commit_verified_registration(
            user_id=user_id,
            challenge_record_id=challenge["id"],
            credential_id="rollback-registration-credential",
            public_key=b"verified-public-key",
        )

    assert repository.list_credentials(user_id) == []
    assert repository.get_challenge(user_id, challenge["id"])["consumed_at"] is None

