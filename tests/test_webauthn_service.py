import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from backend.app.auth import webauthn_service as service_module
from backend.app.auth.webauthn_service import WebAuthnService
from backend.app.config import Settings
from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.persistence.webauthn import WebAuthnRepository
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url


def create_service(tmp_path, *, enabled=True, credential_id=None):
    database = Database(f"sqlite:///{tmp_path / 'service.db'}")

    user_id = str(uuid.uuid4())
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
                user_id,
                f"{user_id}@example.com",
                "test-password-salt",
                "test-password-hash",
                "Test User",
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    tool_requests = ToolRequestRepository(database)
    repository = WebAuthnRepository(database)

    request = tool_requests.create(
        user_id,
        tool_id="test-state-change",
        arguments={"value": "test"},
        status="pending",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )

    if credential_id is not None:
        repository.create_credential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=b"test-public-key",
            sign_count=0,
            transports=("internal", "cable"),
        )

    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'service.db'}",
        webauthn_enabled=enabled,
        webauthn_rp_id="example.com",
        webauthn_allowed_origins=("https://example.com",),
        webauthn_challenge_ttl_seconds=300,
    )

    service = WebAuthnService(
        repository=repository,
        tool_requests=tool_requests,
        settings=settings,
    )

    return database, user_id, request, repository, service


def challenge_count(database):
    return database.connect().execute(
        "SELECT COUNT(*) FROM webauthn_challenges"
    ).fetchone()[0]


def test_create_options_returns_request_bound_authentication_options(tmp_path):
    credential_id = bytes_to_base64url(b"test-credential-id")
    database, user_id, request, repository, service = create_service(
        tmp_path,
        credential_id=credential_id,
    )

    result = service.create_tool_approval_options(
        user_id=user_id,
        request_id=request["id"],
    )

    assert result["challenge_record_id"]
    options = result["options"]

    assert options["rpId"] == "example.com"
    assert options["userVerification"] == "required"
    assert options["challenge"]
    assert options["allowCredentials"][0]["id"] == credential_id

    challenge = repository.get_challenge(
        user_id,
        result["challenge_record_id"],
    )

    assert challenge is not None
    assert challenge["purpose"] == "tool_approval"
    assert challenge["request_id"] == request["id"]
    assert challenge["proposal_digest"]
    assert challenge["contract_fingerprint"] == "a" * 64
    assert challenge["consumed_at"] is None

    raw_challenge = base64url_to_bytes(options["challenge"])
    assert challenge["challenge_hash"] == hashlib.sha256(
        raw_challenge
    ).hexdigest()

    assert challenge_count(database) == 1


def test_option_generation_failure_does_not_persist_challenge(
    tmp_path,
    monkeypatch,
):
    credential_id = bytes_to_base64url(b"test-credential-id")
    database, user_id, request, _, service = create_service(
        tmp_path,
        credential_id=credential_id,
    )

    def fail_generation(**kwargs):
        raise RuntimeError("simulated option-generation failure")

    monkeypatch.setattr(
        service_module,
        "generate_authentication_options",
        fail_generation,
    )

    with pytest.raises(RuntimeError):
        service.create_tool_approval_options(
            user_id=user_id,
            request_id=request["id"],
        )

    assert challenge_count(database) == 0


def test_invalid_stored_credential_id_is_rejected_without_challenge(
    tmp_path,
):
    database, user_id, request, _, service = create_service(
        tmp_path,
        credential_id="not-valid-base64url!",
    )

    with pytest.raises(PermissionError, match="credential ID"):
        service.create_tool_approval_options(
            user_id=user_id,
            request_id=request["id"],
        )

    assert challenge_count(database) == 0


def test_disabled_webauthn_cannot_create_options(tmp_path):
    credential_id = bytes_to_base64url(b"test-credential-id")
    database, user_id, request, _, service = create_service(
        tmp_path,
        enabled=False,
        credential_id=credential_id,
    )

    with pytest.raises(PermissionError, match="not enabled"):
        service.create_tool_approval_options(
            user_id=user_id,
            request_id=request["id"],
        )

    assert challenge_count(database) == 0


def create_approval_attempt(tmp_path):
    credential_id = bytes_to_base64url(b"test-credential-id")
    database, user_id, request, repository, service = create_service(
        tmp_path,
        credential_id=credential_id,
    )

    options_result = service.create_tool_approval_options(
        user_id=user_id,
        request_id=request["id"],
    )

    return (
        database,
        user_id,
        request,
        repository,
        service,
        options_result["challenge_record_id"],
    )


def test_malformed_assertion_does_not_consume_challenge_or_request(tmp_path):
    (
        database,
        user_id,
        request,
        repository,
        service,
        challenge_id,
    ) = create_approval_attempt(tmp_path)

    credential = repository.list_credentials(user_id)[0]

    with pytest.raises(PermissionError, match="verification failed"):
        service.verify_tool_approval(
            user_id=user_id,
            request_id=request["id"],
            challenge_record_id=challenge_id,
            credential_record_id=credential["id"],
            assertion={},
        )

    challenge = repository.get_challenge(user_id, challenge_id)
    updated_request = service.tool_requests.get(user_id, request["id"])

    assert challenge["consumed_at"] is None
    assert updated_request["status"] == "pending"
    assert updated_request["consumed_at"] is None
    assert challenge_count(database) == 1


def test_challenge_bound_to_another_request_is_rejected(tmp_path):
    (
        database,
        user_id,
        request,
        repository,
        service,
        challenge_id,
    ) = create_approval_attempt(tmp_path)

    other_request = service.tool_requests.create(
        user_id,
        tool_id="test-state-change",
        arguments={"value": "test"},
        status="pending",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )

    database.connect().execute(
        """
        UPDATE webauthn_challenges
        SET request_id = ?
        WHERE id = ?
        """,
        (other_request["id"], challenge_id),
    )
    database.connect().commit()

    credential = repository.list_credentials(user_id)[0]

    with pytest.raises(PermissionError, match="does not match"):
        service.verify_tool_approval(
            user_id=user_id,
            request_id=request["id"],
            challenge_record_id=challenge_id,
            credential_record_id=credential["id"],
            assertion={},
        )

    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert service.tool_requests.get(user_id, request["id"])["status"] == "pending"


def test_expired_challenge_is_rejected(tmp_path):
    (
        database,
        user_id,
        request,
        repository,
        service,
        challenge_id,
    ) = create_approval_attempt(tmp_path)

    expired = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()

    database.connect().execute(
        """
        UPDATE webauthn_challenges
        SET expires_at = ?
        WHERE id = ?
        """,
        (expired, challenge_id),
    )
    database.connect().commit()

    credential = repository.list_credentials(user_id)[0]

    with pytest.raises(PermissionError, match="expired"):
        service.verify_tool_approval(
            user_id=user_id,
            request_id=request["id"],
            challenge_record_id=challenge_id,
            credential_record_id=credential["id"],
            assertion={},
        )

    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert service.tool_requests.get(user_id, request["id"])["status"] == "pending"


def test_revoked_credential_cannot_authorize_request(tmp_path):
    (
        database,
        user_id,
        request,
        repository,
        service,
        challenge_id,
    ) = create_approval_attempt(tmp_path)

    credential = repository.list_credentials(user_id)[0]
    repository.revoke_credential(user_id, credential["id"])

    with pytest.raises(PermissionError, match="revoked"):
        service.verify_tool_approval(
            user_id=user_id,
            request_id=request["id"],
            challenge_record_id=challenge_id,
            credential_record_id=credential["id"],
            assertion={},
        )

    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert service.tool_requests.get(user_id, request["id"])["status"] == "pending"


def test_challenge_is_not_visible_to_another_user(tmp_path):
    (
        database,
        user_id,
        request,
        repository,
        service,
        challenge_id,
    ) = create_approval_attempt(tmp_path)

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
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    other_request = service.tool_requests.create(
        other_user_id,
        tool_id="test-state-change",
        arguments={"value": "test"},
        status="pending",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )

    with pytest.raises(LookupError, match="challenge not found"):
        service.verify_tool_approval(
            user_id=other_user_id,
            request_id=other_request["id"],
            challenge_record_id=challenge_id,
            credential_record_id=str(uuid.uuid4()),
            assertion={},
        )

    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert service.tool_requests.get(user_id, request["id"])["status"] == "pending"


def create_signed_assertion(options, credential_id, private_key, *, sign_count=1):
    """Create a genuine ES256 WebAuthn assertion for service-level tests."""
    client_data_json = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": options["challenge"],
            "origin": "https://example.com",
        },
        separators=(",", ":"),
    ).encode("utf-8")

    authenticator_data = (
        hashlib.sha256(b"example.com").digest()
        + b"\x05"  # User Present + User Verified
        + sign_count.to_bytes(4, "big")
    )

    signature_base = authenticator_data + hashlib.sha256(
        client_data_json
    ).digest()

    signature = private_key.sign(
        signature_base,
        ec.ECDSA(hashes.SHA256()),
    )

    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "authenticatorData": bytes_to_base64url(authenticator_data),
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "signature": bytes_to_base64url(signature),
            "userHandle": None,
        },
        "clientExtensionResults": {},
    }


def create_cryptographic_approval_attempt(tmp_path):
    credential_id = bytes_to_base64url(b"test-credential-id")
    database, user_id, request, repository, service = create_service(
        tmp_path,
        credential_id=credential_id,
    )

    credential = repository.list_credentials(user_id)[0]
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()

    cose_public_key = cbor2.dumps(
        {
            1: 2,       # EC2 key type
            3: -7,      # ES256 algorithm
            -1: 1,      # P-256 curve
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    )

    with database.transaction():
        database.connect().execute(
            """
            UPDATE webauthn_credentials
            SET public_key = ?
            WHERE id = ? AND user_id = ?
            """,
            (cose_public_key, credential["id"], user_id),
        )

    options_result = service.create_tool_approval_options(
        user_id=user_id,
        request_id=request["id"],
    )

    assertion = create_signed_assertion(
        options_result["options"],
        credential_id,
        private_key,
    )

    return (
        database,
        user_id,
        request,
        repository,
        service,
        options_result["challenge_record_id"],
        credential,
        assertion,
    )


def test_valid_signed_assertion_authorizes_request_atomically(tmp_path):
    (
        database,
        user_id,
        request,
        repository,
        service,
        challenge_id,
        credential,
        assertion,
    ) = create_cryptographic_approval_attempt(tmp_path)

    authorization = service.verify_tool_approval(
        user_id=user_id,
        request_id=request["id"],
        challenge_record_id=challenge_id,
        credential_record_id=credential["id"],
        assertion=assertion,
    )

    assert authorization["request_id"] == request["id"]
    assert authorization["challenge_id"] == challenge_id
    assert authorization["credential_id"] == credential["id"]
    assert authorization["proposal_digest"]

    updated_request = service.tool_requests.get(user_id, request["id"])
    updated_challenge = repository.get_challenge(user_id, challenge_id)
    updated_credential = repository.get_credential(user_id, credential["id"])

    assert updated_request["status"] == "executing"
    assert updated_request["consumed_at"] is not None
    assert updated_challenge["consumed_at"] is not None
    assert updated_credential["sign_count"] == 1
    assert updated_credential["last_used_at"] is not None

    authorization_count = database.connect().execute(
        """
        SELECT COUNT(*)
        FROM tool_authorizations
        WHERE user_id = ? AND request_id = ?
        """,
        (user_id, request["id"]),
    ).fetchone()[0]

    assert authorization_count == 1


def test_tampered_signature_does_not_consume_challenge_or_request(tmp_path):
    (
        database,
        user_id,
        request,
        repository,
        service,
        challenge_id,
        credential,
        assertion,
    ) = create_cryptographic_approval_attempt(tmp_path)

    tampered_assertion = json.loads(json.dumps(assertion))
    signature = bytearray(
        base64url_to_bytes(tampered_assertion["response"]["signature"])
    )
    signature[-1] ^= 0x01
    tampered_assertion["response"]["signature"] = bytes_to_base64url(
        bytes(signature)
    )

    with pytest.raises(PermissionError, match="verification failed"):
        service.verify_tool_approval(
            user_id=user_id,
            request_id=request["id"],
            challenge_record_id=challenge_id,
            credential_record_id=credential["id"],
            assertion=tampered_assertion,
        )

    updated_request = service.tool_requests.get(user_id, request["id"])
    updated_challenge = repository.get_challenge(user_id, challenge_id)
    updated_credential = repository.get_credential(user_id, credential["id"])

    assert updated_request["status"] == "pending"
    assert updated_request["consumed_at"] is None
    assert updated_challenge["consumed_at"] is None
    assert updated_credential["sign_count"] == 0
    assert updated_credential["last_used_at"] is None

    authorization_count = database.connect().execute(
        """
        SELECT COUNT(*)
        FROM tool_authorizations
        WHERE user_id = ? AND request_id = ?
        """,
        (user_id, request["id"]),
    ).fetchone()[0]

    assert authorization_count == 0

def create_registration_credential(options, *, origin="https://example.com"):
    """Build a genuine none-attestation registration response using ES256."""
    credential_id_bytes = b"registration-credential-id"
    credential_id = bytes_to_base64url(credential_id_bytes)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()

    cose_public_key = cbor2.dumps(
        {
            1: 2,       # EC2 key type
            3: -7,      # ES256 algorithm
            -1: 1,      # P-256 curve
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    )

    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": options["challenge"],
            "origin": origin,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    authenticator_data = (
        hashlib.sha256(b"example.com").digest()
        + b"\x45"  # User Present + User Verified + Attested Credential Data
        + b"\x00\x00\x00\x00"  # Initial signature counter
        + b"\x00" * 16  # AAGUID
        + len(credential_id_bytes).to_bytes(2, "big")
        + credential_id_bytes
        + cose_public_key
    )

    attestation_object = cbor2.dumps(
        {
            "fmt": "none",
            "attStmt": {},
            "authData": authenticator_data,
        }
    )

    credential = {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "attestationObject": bytes_to_base64url(attestation_object),
            "transports": ["internal"],
        },
    }

    return credential, credential_id, cose_public_key


def create_registration_attempt(tmp_path, *, origin="https://example.com"):
    database, user_id, _, repository, service = create_service(tmp_path)

    options_result = service.create_registration_options(
        user_id=user_id,
        user_name=f"{user_id}@example.com",
        user_display_name="Test User",
    )

    credential, credential_id, public_key = create_registration_credential(
        options_result["options"],
        origin=origin,
    )

    return (
        database,
        user_id,
        repository,
        service,
        options_result["challenge_record_id"],
        credential,
        credential_id,
        public_key,
    )


def test_valid_registration_verifies_and_saves_credential_atomically(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        challenge_id,
        credential,
        credential_id,
        public_key,
    ) = create_registration_attempt(tmp_path)

    saved = service.verify_registration(
        user_id=user_id,
        challenge_record_id=challenge_id,
        credential=credential,
        name="My test passkey",
    )

    assert saved["credential_id"] == credential_id
    assert saved["public_key"] == public_key
    assert saved["sign_count"] == 0
    assert saved["transports"] == ["internal"]
    assert saved["name"] == "My test passkey"

    challenge = repository.get_challenge(user_id, challenge_id)
    assert challenge["consumed_at"] is not None

    credentials = repository.list_credentials(user_id)
    assert len(credentials) == 1
    assert credentials[0]["credential_id"] == credential_id

    assert challenge_count(database) == 1


def test_tampered_registration_challenge_does_not_save_credential(
    tmp_path,
):
    (
        database,
        user_id,
        repository,
        service,
        challenge_id,
        credential,
        _,
        _,
    ) = create_registration_attempt(tmp_path)

    tampered = json.loads(json.dumps(credential))
    client_data = json.loads(
        base64url_to_bytes(
            tampered["response"]["clientDataJSON"]
        )
    )
    client_data["challenge"] = bytes_to_base64url(b"wrong-challenge")
    tampered["response"]["clientDataJSON"] = bytes_to_base64url(
        json.dumps(client_data, separators=(",", ":")).encode("utf-8")
    )

    with pytest.raises(PermissionError, match="challenge does not match"):
        service.verify_registration(
            user_id=user_id,
            challenge_record_id=challenge_id,
            credential=tampered,
        )

    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert repository.list_credentials(user_id) == []
    assert challenge_count(database) == 1




def test_registration_challenge_cannot_be_replayed(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        challenge_id,
        credential,
        _,
        _,
    ) = create_registration_attempt(tmp_path)

    service.verify_registration(
        user_id=user_id,
        challenge_record_id=challenge_id,
        credential=credential,
    )

    with pytest.raises(PermissionError, match="not available"):
        service.verify_registration(
            user_id=user_id,
            challenge_record_id=challenge_id,
            credential=credential,
        )

    assert len(repository.list_credentials(user_id)) == 1
    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is not None
    assert challenge_count(database) == 1


def test_expired_registration_challenge_is_rejected(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        challenge_id,
        credential,
        _,
        _,
    ) = create_registration_attempt(tmp_path)

    expired = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()

    database.connect().execute(
        "UPDATE webauthn_challenges SET expires_at = ? WHERE id = ?",
        (expired, challenge_id),
    )
    database.connect().commit()

    with pytest.raises(PermissionError, match="expired"):
        service.verify_registration(
            user_id=user_id,
            challenge_record_id=challenge_id,
            credential=credential,
        )

    assert repository.list_credentials(user_id) == []
    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert challenge_count(database) == 1


def test_wrong_purpose_challenge_cannot_register_credential(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        challenge_id,
        credential,
        _,
        _,
    ) = create_registration_attempt(tmp_path)

    database.connect().execute(
        "UPDATE webauthn_challenges SET purpose = 'tool_approval' WHERE id = ?",
        (challenge_id,),
    )
    database.connect().commit()

    with pytest.raises(PermissionError, match="not available"):
        service.verify_registration(
            user_id=user_id,
            challenge_record_id=challenge_id,
            credential=credential,
        )

    assert repository.list_credentials(user_id) == []
    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert challenge_count(database) == 1


def test_duplicate_credential_id_does_not_consume_registration_challenge(
    tmp_path,
):
    (
        database,
        user_id,
        repository,
        service,
        challenge_id,
        credential,
        credential_id,
        public_key,
    ) = create_registration_attempt(tmp_path)

    repository.create_credential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=public_key,
    )

    with pytest.raises(Exception) as exc_info:
        service.verify_registration(
            user_id=user_id,
            challenge_record_id=challenge_id,
            credential=credential,
        )

    import sqlite3
    assert isinstance(exc_info.value, sqlite3.IntegrityError)

    assert len(repository.list_credentials(user_id)) == 1
    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert challenge_count(database) == 1


def test_registration_from_untrusted_origin_is_rejected(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        challenge_id,
        credential,
        _,
        _,
    ) = create_registration_attempt(
        tmp_path,
        origin="https://evil.example",
    )

    with pytest.raises(PermissionError, match="verification failed"):
        service.verify_registration(
            user_id=user_id,
            challenge_record_id=challenge_id,
            credential=credential,
        )

    assert repository.get_challenge(user_id, challenge_id)["consumed_at"] is None
    assert repository.list_credentials(user_id) == []
    assert challenge_count(database) == 1



def create_cryptographic_authentication_attempt(tmp_path):
    """Create a real passkey, authentication challenge and signed assertion."""
    credential_id = bytes_to_base64url(b"test-credential-id")
    database, user_id, request, repository, service = create_service(
        tmp_path,
        credential_id=credential_id,
    )

    credential = repository.list_credentials(user_id)[0]
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()

    cose_public_key = cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    )

    with database.transaction():
        database.connect().execute(
            """
            UPDATE webauthn_credentials
            SET public_key = ?
            WHERE id = ? AND user_id = ?
            """,
            (cose_public_key, credential["id"], user_id),
        )

    options_result = service.create_authentication_options(
        user_id=user_id,
    )

    assertion = create_signed_assertion(
        options_result["options"],
        credential_id,
        private_key,
    )

    return (
        database,
        user_id,
        repository,
        service,
        options_result,
        credential,
        assertion,
    )


def test_create_authentication_options_returns_account_bound_options(tmp_path):
    credential_id = bytes_to_base64url(b"test-credential-id")
    database, user_id, _, repository, service = create_service(
        tmp_path,
        credential_id=credential_id,
    )

    result = service.create_authentication_options(user_id=user_id)

    assert result["challenge_record_id"]
    assert result["options"]["rpId"] == "example.com"
    assert result["options"]["userVerification"] == "required"
    assert result["options"]["allowCredentials"][0]["id"] == credential_id

    challenge = repository.get_challenge(
        user_id,
        result["challenge_record_id"],
    )
    raw_challenge = base64url_to_bytes(result["options"]["challenge"])

    assert challenge["purpose"] == "authentication"
    assert challenge["request_id"] is None
    assert challenge["consumed_at"] is None
    assert challenge["challenge_hash"] == hashlib.sha256(
        raw_challenge
    ).hexdigest()
    assert challenge_count(database) == 1


def test_valid_signed_passkey_authentication_updates_credential(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        options_result,
        credential,
        assertion,
    ) = create_cryptographic_authentication_attempt(tmp_path)

    authenticated = service.verify_authentication(
        user_id=user_id,
        challenge_record_id=options_result["challenge_record_id"],
        assertion=assertion,
    )

    assert authenticated["id"] == credential["id"]
    assert authenticated["sign_count"] == 1
    assert authenticated["last_used_at"] is not None

    challenge = repository.get_challenge(
        user_id,
        options_result["challenge_record_id"],
    )
    assert challenge["consumed_at"] is not None


def test_tampered_passkey_assertion_does_not_consume_challenge(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        options_result,
        credential,
        assertion,
    ) = create_cryptographic_authentication_attempt(tmp_path)

    tampered = json.loads(json.dumps(assertion))
    signature = bytearray(
        base64url_to_bytes(tampered["response"]["signature"])
    )
    signature[-1] ^= 0x01
    tampered["response"]["signature"] = bytes_to_base64url(
        bytes(signature)
    )

    with pytest.raises(PermissionError, match="verification failed"):
        service.verify_authentication(
            user_id=user_id,
            challenge_record_id=options_result["challenge_record_id"],
            assertion=tampered,
        )

    challenge = repository.get_challenge(
        user_id,
        options_result["challenge_record_id"],
    )
    unchanged = repository.get_credential(user_id, credential["id"])

    assert challenge["consumed_at"] is None
    assert unchanged["sign_count"] == 0
    assert unchanged["last_used_at"] is None


def test_expired_passkey_authentication_challenge_is_rejected(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        options_result,
        credential,
        assertion,
    ) = create_cryptographic_authentication_attempt(tmp_path)

    expired = (
        datetime.now(timezone.utc) - timedelta(minutes=1)
    ).isoformat()

    with database.transaction():
        database.connect().execute(
            """
            UPDATE webauthn_challenges
            SET expires_at = ?
            WHERE id = ?
            """,
            (expired, options_result["challenge_record_id"]),
        )

    with pytest.raises(PermissionError, match="expired"):
        service.verify_authentication(
            user_id=user_id,
            challenge_record_id=options_result["challenge_record_id"],
            assertion=assertion,
        )

    challenge = repository.get_challenge(
        user_id,
        options_result["challenge_record_id"],
    )
    assert challenge["consumed_at"] is None


def test_passkey_authentication_challenge_cannot_be_replayed(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        options_result,
        credential,
        assertion,
    ) = create_cryptographic_authentication_attempt(tmp_path)

    service.verify_authentication(
        user_id=user_id,
        challenge_record_id=options_result["challenge_record_id"],
        assertion=assertion,
    )

    with pytest.raises(PermissionError, match="unavailable"):
        service.verify_authentication(
            user_id=user_id,
            challenge_record_id=options_result["challenge_record_id"],
            assertion=assertion,
        )

    updated = repository.get_credential(user_id, credential["id"])
    assert updated["sign_count"] == 1


def test_revoked_passkey_cannot_authenticate(tmp_path):
    (
        database,
        user_id,
        repository,
        service,
        options_result,
        credential,
        assertion,
    ) = create_cryptographic_authentication_attempt(tmp_path)

    repository.revoke_credential(user_id, credential["id"])

    with pytest.raises(PermissionError, match="revoked"):
        service.verify_authentication(
            user_id=user_id,
            challenge_record_id=options_result["challenge_record_id"],
            assertion=assertion,
        )

    challenge = repository.get_challenge(
        user_id,
        options_result["challenge_record_id"],
    )
    assert challenge["consumed_at"] is None
