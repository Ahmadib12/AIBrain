from datetime import datetime, timedelta, timezone
import hashlib
import json

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

import backend.app.auth.webauthn_service as webauthn_service_module
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url

from backend.app.app_state import get_app_state
from backend.app.main import app
from backend.app.api.v1.tools import tool_registry
from backend.app.tools import ToolContract, ToolRisk


@pytest.fixture
def client():
    get_app_state()
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(client: TestClient, email: str) -> str:
    registered = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "safe-password-123",
            "display_name": "Tool API Test",
        },
    )
    assert registered.status_code == 200

    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "safe-password-123",
        },
    )
    assert login.status_code == 200
    return login.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def state_change_contract() -> ToolContract:
    return ToolContract(
        tool_id="state-change-api-test",
        name="State change API test",
        description="Test-only state-changing tool",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={
            "type": "object",
            "properties": {
                "value": {"type": "string", "maxLength": 100},
            },
            "required": ["value"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


def test_state_change_proposal_cannot_be_confirmed_without_human_authorization(
    client: TestClient,
    monkeypatch,
) -> None:
    contract = state_change_contract()
    monkeypatch.setitem(tool_registry._tools, contract.tool_id, contract)

    token = register_and_login(client, "tool-proposal-api@example.com")
    headers = auth_header(token)

    proposed = client.post(
        "/api/v1/tools/requests",
        headers=headers,
        json={
            "tool_id": contract.tool_id,
            "arguments": {"value": "review this action"},
        },
    )

    assert proposed.status_code == 200
    proposal = proposed.json()
    assert proposal["tool_id"] == contract.tool_id
    assert proposal["arguments"] == {"value": "review this action"}
    assert proposal["status"] == "pending"

    confirmed = client.post(
        f"/api/v1/tools/requests/{proposal['id']}/confirm",
        headers=headers,
    )

    assert confirmed.status_code == 409
    assert (
        confirmed.json()["error"]["code"]
        == "CONFIRMATION_NOT_AVAILABLE"
    )

    state = get_app_state()
    persisted = state.tool_requests.get(
        state.identity.resolve_token(token)["id"],
        proposal["id"],
    )
    assert persisted["status"] == "pending"
    assert persisted["consumed_at"] is None
    assert persisted["result"] is None


def test_immediate_execution_rejects_state_change_before_persistence(
    client: TestClient,
    monkeypatch,
) -> None:
    contract = state_change_contract()
    monkeypatch.setitem(tool_registry._tools, contract.tool_id, contract)

    token = register_and_login(client, "tool-execute-blocked@example.com")
    user_id = get_app_state().identity.resolve_token(token)["id"]

    response = client.post(
        "/api/v1/tools/execute",
        headers=auth_header(token),
        json={
            "tool_id": contract.tool_id,
            "arguments": {"value": "must not be persisted"},
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CONFIRMATION_REQUIRED"

    state = get_app_state()
    count = state.database.connect().execute(
        "SELECT COUNT(*) FROM tool_requests "
        "WHERE user_id = ? AND tool_id = ?",
        (user_id, contract.tool_id),
    ).fetchone()[0]
    assert count == 0



def test_passkey_options_endpoint_is_authenticated_and_request_scoped(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    owner_token = register_and_login(client, "passkey-options-owner@example.com")
    other_token = register_and_login(client, "passkey-options-other@example.com")
    owner_id = state.identity.resolve_token(owner_token)["id"]

    request = state.tool_requests.create(
        owner_id,
        tool_id="state-change-api-test",
        arguments={"value": "sensitive action"},
        status="pending",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )

    # Bypass the feature-availability guard so this test reaches the
    # request lookup and verifies cross-account resource isolation.
    monkeypatch.setattr(
        state.webauthn_service,
        "_require_enabled",
        lambda: None,
    )

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/passkey/options",
        headers=auth_header(other_token),
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TOOL_REQUEST_NOT_FOUND"


def test_passkey_options_endpoint_returns_service_options_without_exposing_records(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-options-api@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    captured = {}

    def create_options(*, user_id: str, request_id: str) -> dict:
        captured["user_id"] = user_id
        captured["request_id"] = request_id
        return {
            "challenge_record_id": "challenge-record",
            "options": {"challenge": "browser-challenge"},
        }

    monkeypatch.setattr(
        state.webauthn_service,
        "create_tool_approval_options",
        create_options,
    )

    response = client.post(
        "/api/v1/tools/requests/request-123/passkey/options",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    assert response.json() == {
        "challenge_record_id": "challenge-record",
        "options": {"challenge": "browser-challenge"},
    }
    assert captured == {
        "user_id": user_id,
        "request_id": "request-123",
    }


def test_passkey_verify_endpoint_returns_only_approved_request_metadata(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-verify-api@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = state.tool_requests.create(
        user_id,
        tool_id="state-change-api-test",
        arguments={"value": "approved"},
        status="pending",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )
    captured = {}

    def verify_approval(
        *,
        user_id: str,
        request_id: str,
        challenge_record_id: str,
        credential_record_id: str,
        assertion: dict,
    ) -> dict:
        captured.update({
            "user_id": user_id,
            "request_id": request_id,
            "challenge_record_id": challenge_record_id,
            "credential_record_id": credential_record_id,
            "assertion": assertion,
        })
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE tool_requests SET status = 'approved', updated_at = ? WHERE id = ? AND user_id = ?",
                (datetime.now(timezone.utc).isoformat(), request_id, user_id),
            )
        return {"authorization_id": "internal-authorization"}

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_tool_approval",
        verify_approval,
    )

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/passkey/verify",
        headers=auth_header(token),
        json={
            "challenge_record_id": "challenge-456",
            "credential_record_id": "credential-456",
            "assertion": {"response": {"signature": "browser-data"}},
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": request["id"],
        "tool_id": "state-change-api-test",
        "arguments": {"value": "approved"},
        "status": "approved",
        "expires_at": request["expires_at"],
    }
    assert captured == {
        "user_id": user_id,
        "request_id": request["id"],
        "challenge_record_id": "challenge-456",
        "credential_record_id": "credential-456",
        "assertion": {"response": {"signature": "browser-data"}},
    }


def test_passkey_verify_endpoint_hides_assertion_verification_details(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-verify-rejected@example.com")

    def reject_assertion(**kwargs):
        raise PermissionError("Detailed cryptographic failure")

    monkeypatch.setattr(
        state.webauthn_service,
        "verify_tool_approval",
        reject_assertion,
    )

    response = client.post(
        "/api/v1/tools/requests/request-789/passkey/verify",
        headers=auth_header(token),
        json={
            "challenge_record_id": "challenge-789",
            "credential_record_id": "credential-789",
            "assertion": {},
        },
    )

    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "PASSKEY_APPROVAL_REJECTED"
    assert error["message"] == "Passkey approval could not be verified"
    assert "Detailed cryptographic failure" not in response.text



def test_passkey_api_uses_real_service_and_preserves_pending_state(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-real-service-api@example.com")
    user_id = state.identity.resolve_token(token)["id"]

    request = state.tool_requests.create(
        user_id,
        tool_id="state-change-api-test",
        arguments={"value": "review before execution"},
        status="pending",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )
    credential_id = bytes_to_base64url(b"api-integration-credential")
    state.webauthn.create_credential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=b"test-public-key",
        sign_count=0,
        transports=("internal",),
    )

    # Keep the real service, repository, challenge binding, and API route.
    # Only replace option serialization so this test does not depend on a
    # browser authenticator or real WebAuthn cryptographic material.
    monkeypatch.setattr(
        state.webauthn_service,
        "_require_enabled",
        lambda: None,
    )
    monkeypatch.setattr(
        webauthn_service_module,
        "generate_authentication_options",
        lambda **kwargs: object(),
    )
    monkeypatch.setattr(
        webauthn_service_module,
        "options_to_json",
        lambda options: json.dumps({"challenge": "test-browser-challenge"}),
    )

    options_response = client.post(
        f"/api/v1/tools/requests/{request['id']}/passkey/options",
        headers=auth_header(token),
    )

    assert options_response.status_code == 200
    options_body = options_response.json()
    assert options_body["options"]["challenge"] == "test-browser-challenge"

    challenge = state.webauthn.get_challenge(
        user_id,
        options_body["challenge_record_id"],
    )
    assert challenge is not None
    assert challenge["purpose"] == "tool_approval"
    assert challenge["request_id"] == request["id"]
    assert challenge["consumed_at"] is None

    credential = state.webauthn.list_credentials(user_id)[0]
    verify_response = client.post(
        f"/api/v1/tools/requests/{request['id']}/passkey/verify",
        headers=auth_header(token),
        json={
            "challenge_record_id": challenge["id"],
            "credential_record_id": credential["id"],
            "assertion": {},
        },
    )

    assert verify_response.status_code == 409
    assert (
        verify_response.json()["error"]["code"]
        == "PASSKEY_APPROVAL_REJECTED"
    )

    persisted_request = state.tool_requests.get(user_id, request["id"])
    persisted_challenge = state.webauthn.get_challenge(
        user_id,
        challenge["id"],
    )
    assert persisted_request["status"] == "pending"
    assert persisted_request["consumed_at"] is None
    assert persisted_challenge["consumed_at"] is None



def test_passkey_api_completes_real_signed_approval(
    client: TestClient,
    monkeypatch,
) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-success-api@example.com")
    user_id = state.identity.resolve_token(token)["id"]

    request = state.tool_requests.create(
        user_id,
        tool_id="state-change-api-test",
        arguments={"value": "explicitly approved"},
        status="pending",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )

    credential_id = bytes_to_base64url(b"api-real-signed-credential")
    credential = state.webauthn.create_credential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=b"placeholder-public-key",
        sign_count=0,
        transports=("internal",),
    )

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    cose_public_key = cbor2.dumps({
        1: 2,
        3: -7,
        -1: 1,
        -2: public_numbers.x.to_bytes(32, "big"),
        -3: public_numbers.y.to_bytes(32, "big"),
    })
    with state.database.transaction():
        state.database.connect().execute(
            "UPDATE webauthn_credentials SET public_key = ? WHERE id = ? AND user_id = ?",
            (cose_public_key, credential["id"], user_id),
        )

    # Supply a valid test RP configuration while retaining real WebAuthn
    # option generation, assertion parsing, signature verification and API.
    state.webauthn_service.settings = state.webauthn_service.settings.model_copy(
        update={
            "webauthn_enabled": True,
            "webauthn_rp_id": "example.com",
            "webauthn_allowed_origins": ("https://example.com",),
        }
    )

    options_response = client.post(
        f"/api/v1/tools/requests/{request['id']}/passkey/options",
        headers=auth_header(token),
    )
    assert options_response.status_code == 200
    options_body = options_response.json()

    challenge = state.webauthn.get_challenge(
        user_id,
        options_body["challenge_record_id"],
    )
    assert challenge["request_id"] == request["id"]
    assert challenge["consumed_at"] is None

    client_data_json = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": options_body["options"]["challenge"],
            "origin": "https://example.com",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    authenticator_data = (
        hashlib.sha256(b"example.com").digest()
        + b"\x05"
        + (1).to_bytes(4, "big")
    )
    signature_base = (
        authenticator_data + hashlib.sha256(client_data_json).digest()
    )
    signature = private_key.sign(
        signature_base,
        ec.ECDSA(hashes.SHA256()),
    )
    assertion = {
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

    verify_response = client.post(
        f"/api/v1/tools/requests/{request['id']}/passkey/verify",
        headers=auth_header(token),
        json={
            "challenge_record_id": challenge["id"],
            "credential_record_id": credential["id"],
            "assertion": assertion,
        },
    )

    assert verify_response.status_code == 200
    assert verify_response.json() == {
        "id": request["id"],
        "tool_id": "state-change-api-test",
        "arguments": {"value": "explicitly approved"},
        "status": "approved",
        "expires_at": request["expires_at"],
    }

    persisted_request = state.tool_requests.get(user_id, request["id"])
    persisted_challenge = state.webauthn.get_challenge(
        user_id,
        challenge["id"],
    )
    persisted_credential = state.webauthn.get_credential(
        user_id,
        credential["id"],
    )
    authorization_count = state.database.connect().execute(
        "SELECT COUNT(*) FROM tool_authorizations WHERE request_id = ?",
        (request["id"],),
    ).fetchone()[0]

    assert persisted_request["status"] == "approved"
    assert persisted_request["consumed_at"] is None
    assert persisted_challenge["consumed_at"] is not None
    assert persisted_credential["sign_count"] == 1
    assert authorization_count == 1

    # Passkey approval is authorization evidence, not permission to dispatch.
    from backend.app.api.v1.tools import _get_tool_gateway

    gateway = _get_tool_gateway()
    from backend.app.tools import ToolContract, ToolRisk

    # Register the persisted tool contract in the API gateway's registry so
    # execution reaches the state-change policy check (rather than tool lookup).
    gateway.registry.register(ToolContract(
        tool_id="state-change-api-test",
        name="State-change API test",
        description="Test-only state-changing tool",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        output_schema={"result": {"type": "string"}},
    ))
    with pytest.raises(PermissionError, match="complete confirmation policy"):
        gateway.execute(
            {
                "id": request["id"],
                "user_id": user_id,
            },
            user_id=user_id,
        )

    unchanged_request = state.tool_requests.get(user_id, request["id"])
    assert unchanged_request["status"] == "approved"
    assert unchanged_request["consumed_at"] is None



def test_owner_can_cancel_approved_passkey_request(client: TestClient) -> None:
    state = get_app_state()
    token = register_and_login(client, "passkey-cancel-approved@example.com")
    user_id = state.identity.resolve_token(token)["id"]
    request = state.tool_requests.create(
        user_id,
        tool_id="state-change-api-test",
        arguments={"value": "approved but not executed"},
        status="approved",
        expires_at=(
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        contract_fingerprint="a" * 64,
        authorization_policy="passkey",
    )

    response = client.post(
        f"/api/v1/tools/requests/{request['id']}/cancel",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    persisted = state.tool_requests.get(user_id, request["id"])
    assert persisted["status"] == "cancelled"
    assert persisted["consumed_at"] is None



def test_runner_key_management_requires_security_operator_token_and_never_exposes_public_key(
    client: TestClient, monkeypatch
) -> None:
    import base64
    from backend.app.auth import operator as operator_module
    from backend.app.config import Settings
    from backend.app.tools.attestation import generate_test_keypair

    security_token = "security-test-token-" + "x" * 32
    provider_token = "provider-test-token-" + "p" * 32
    monkeypatch.setattr(
        operator_module, "get_settings",
        lambda: Settings(
            provider_operator_token=provider_token,
            security_operator_token=security_token,
        ),
    )
    public_key, _private_key = generate_test_keypair()
    now = datetime.now(timezone.utc)
    body = {
        "key_id": "api-runner-key",
        "runner_id": "api-runner",
        "provider_id": "api-provider",
        "adapter_id": "api-adapter",
        "adapter_version": "1.0.0",
        "provider_scope": "api-sandbox-account",
        "tool_id": "api-test-tool",
        "tool_contract_fingerprint": "a" * 64,
        "public_key_base64": base64.b64encode(public_key).decode("ascii"),
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(days=2)).isoformat(),
        "registered_by": "security-operator",
    }

    denied = client.post(
        "/api/v1/tools/operator/trusted-runner-keys", json=body
    )
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "SECURITY_OPERATOR_UNAUTHORIZED"

    denied_bad_token = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        headers={"X-AIBrain-Security-Operator-Token": "wrong-token"},
        json=body,
    )
    assert denied_bad_token.status_code == 401

    provider_cannot_register = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        headers={"X-AIBrain-Operator-Token": provider_token},
        json=body,
    )
    assert provider_cannot_register.status_code == 401

    created = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        headers={"X-AIBrain-Security-Operator-Token": security_token},
        json=body,
    )
    assert created.status_code == 201
    assert created.json()["key_id"] == "api-runner-key"
    assert created.json()["algorithm"] == "Ed25519"
    assert "public_key" not in created.json()
    assert "private_key" not in created.json()

    duplicate = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        headers={"X-AIBrain-Security-Operator-Token": security_token},
        json=body,
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "RUNNER_KEY_CONFLICT"

    revoked = client.post(
        "/api/v1/tools/operator/trusted-runner-keys/api-runner-key/revoke",
        headers={"X-AIBrain-Security-Operator-Token": security_token},
        json={
            "revoked_by": "security-operator",
            "reason": "Test key rotation",
        },
    )
    assert revoked.status_code == 200
    assert revoked.json() == {
        "key_id": "api-runner-key",
        "status": "revoked",
    }


def test_runner_key_management_fails_closed_when_operator_auth_unconfigured(
    client: TestClient, monkeypatch
) -> None:
    from backend.app.auth import operator as operator_module
    from backend.app.config import Settings

    monkeypatch.setattr(
        operator_module, "get_settings", lambda: Settings()
    )
    response = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        json={
            "key_id": "no-auth-key",
            "runner_id": "runner",
            "provider_id": "provider",
            "adapter_id": "adapter",
            "adapter_version": "1.0",
            "provider_scope": "sandbox",
            "tool_id": "tool",
            "public_key_base64": "A" * 44,
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "valid_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "registered_by": "operator",
        },
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SECURITY_OPERATOR_AUTH_NOT_CONFIGURED"



def test_runner_ingestion_and_operator_approval_are_separate_privileges(
    client: TestClient, monkeypatch
) -> None:
    import base64
    import hashlib
    from backend.app.auth import operator as operator_module
    from backend.app.config import Settings
    from backend.app.tools.attestation import (
        build_attestation_payload, generate_test_keypair,
        sign_attestation_for_runner,
    )
    from backend.app.tools.conformance import REQUIRED_CHECKS

    security_token = "security-operator-secret-" + "s" * 32
    provider_token = "provider-operator-secret-" + "p" * 32
    runner_token = "runner-ingest-secret-" + "b" * 32
    monkeypatch.setattr(
        operator_module, "get_settings",
        lambda: Settings(
            provider_operator_token=provider_token,
            security_operator_token=security_token,
            trusted_runner_ingest_token=runner_token,
        ),
    )
    now = datetime.now(timezone.utc)
    public_key, private_key = generate_test_keypair()

    # Runner credentials cannot register or revoke signing keys.
    runner_cannot_register = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        headers={"X-AIBrain-Runner-Token": runner_token},
        json={
            "key_id": "e2e-runner-key",
            "runner_id": "e2e-runner",
            "provider_id": "api-provider",
            "adapter_id": "api-adapter",
            "adapter_version": "1.0.0",
            "provider_scope": "sandbox-account",
            "tool_id": "api-test-tool",
            "tool_contract_fingerprint": "c" * 64,
            "public_key_base64": base64.b64encode(public_key).decode("ascii"),
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=2)).isoformat(),
            "registered_by": "security-operator",
        },
    )
    assert runner_cannot_register.status_code == 401

    provider_cannot_register = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        headers={"X-AIBrain-Operator-Token": provider_token},
        json={
            "key_id": "e2e-runner-key",
            "runner_id": "e2e-runner",
            "provider_id": "api-provider",
            "adapter_id": "api-adapter",
            "adapter_version": "1.0.0",
            "provider_scope": "sandbox-account",
            "tool_id": "api-test-tool",
            "tool_contract_fingerprint": "c" * 64,
            "public_key_base64": base64.b64encode(public_key).decode("ascii"),
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=2)).isoformat(),
            "registered_by": "security-operator",
        },
    )
    assert provider_cannot_register.status_code == 401

    # Only the dedicated security operator credential can install the key.
    registered = client.post(
        "/api/v1/tools/operator/trusted-runner-keys",
        headers={"X-AIBrain-Security-Operator-Token": security_token},
        json={
            "key_id": "e2e-runner-key",
            "runner_id": "e2e-runner",
            "provider_id": "api-provider",
            "adapter_id": "api-adapter",
            "adapter_version": "1.0.0",
            "provider_scope": "sandbox-account",
            "tool_id": "api-test-tool",
            "tool_contract_fingerprint": "c" * 64,
            "public_key_base64": base64.b64encode(public_key).decode("ascii"),
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(days=2)).isoformat(),
            "registered_by": "security-operator",
        },
    )
    assert registered.status_code == 201

    report = b"trusted runner integration test report"
    artifacts = {"sandbox-report.bin": report}
    manifest = {
        "schema_version": "aibrain-conformance-evidence-v1",
        "provider_id": "api-provider",
        "adapter_id": "api-adapter",
        "adapter_version": "1.0.0",
        "provider_scope": "sandbox-account",
        "tool_id": "api-test-tool",
        "tool_contract_fingerprint": "c" * 64,
        "capabilities": {
            "idempotency_mode": "provider_enforced",
            "key_scope": "provider-account-and-operation",
            "idempotency_retention_seconds": 3600,
            "rejects_payload_mismatch": True,
            "concurrent_deduplication": True,
            "supports_outcome_lookup": True,
        },
        "test_suite_version": "conformance-v1",
        "sandbox_environment": "isolated-ci-sandbox",
        "executed_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=2)).isoformat(),
        "tests": {
            name: {"status": "passed", "artifact": "sandbox-report.bin"}
            for name in REQUIRED_CHECKS
        },
        "artifacts": {
            "sandbox-report.bin": hashlib.sha256(report).hexdigest()
        },
    }

    # Operator credentials cannot ingest/sign on behalf of the runner.
    operator_cannot_ingest = client.post(
        "/api/v1/tools/runner/evidence",
        headers={"X-AIBrain-Security-Operator-Token": security_token},
        json={
            "manifest": manifest,
            "artifacts_base64": {
                "sandbox-report.bin": base64.b64encode(report).decode("ascii")
            },
        },
    )
    assert operator_cannot_ingest.status_code == 401

    upload = client.post(
        "/api/v1/tools/runner/evidence",
        headers={"X-AIBrain-Runner-Token": runner_token},
        json={
            "manifest": manifest,
            "artifacts_base64": {
                "sandbox-report.bin": base64.b64encode(report).decode("ascii")
            },
        },
    )
    assert upload.status_code == 201
    package = upload.json()
    assert package["provenance"] == "unattested"

    issued_at = datetime.now(timezone.utc).isoformat()
    attestation_expires = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
    nonce = "nonce_" + __import__("uuid").uuid4().hex
    payload_response = client.post(
        f"/api/v1/tools/runner/evidence/{package['package_id']}/attestation-payload",
        headers={"X-AIBrain-Runner-Token": runner_token},
        json={
            "key_id": "e2e-runner-key",
            "runner_id": "e2e-runner",
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": attestation_expires,
        },
    )
    assert payload_response.status_code == 200
    payload = payload_response.json()
    signature = sign_attestation_for_runner(private_key, payload)

    attestation = client.post(
        f"/api/v1/tools/runner/evidence/{package['package_id']}/attest",
        headers={"X-AIBrain-Runner-Token": runner_token},
        json={
            "key_id": "e2e-runner-key",
            "runner_id": "e2e-runner",
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": attestation_expires,
            "signature": signature,
        },
    )
    assert attestation.status_code == 200
    assert attestation.json()["runner_id"] == "e2e-runner"

    # Only a separately authenticated human operator can approve certification.
    runner_cannot_certify = client.post(
        f"/api/v1/tools/operator/evidence/{package['package_id']}/certify",
        headers={"X-AIBrain-Runner-Token": runner_token},
        json={
            "approved_by": "security-reviewer",
            "expires_at": (now + timedelta(hours=6)).isoformat(),
        },
    )
    assert runner_cannot_certify.status_code == 401

    provider_cannot_certify = client.post(
        f"/api/v1/tools/operator/evidence/{package['package_id']}/certify",
        headers={"X-AIBrain-Operator-Token": provider_token},
        json={
            "approved_by": "security-reviewer",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        },
    )
    assert provider_cannot_certify.status_code == 401

    certified = client.post(
        f"/api/v1/tools/operator/evidence/{package['package_id']}/certify",
        headers={"X-AIBrain-Security-Operator-Token": security_token},
        json={
            "approved_by": "security-reviewer",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        },
    )
    assert certified.status_code == 201
    assert certified.json()["approved_by"] == "security-reviewer"
