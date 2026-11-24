import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from backend.app.tools.conformance import REQUIRED_CHECKS, canonical_json
from backend.app.tools.conformance_suite import verify_signed_suite


BINDING = {
    "provider_id": "provider-a",
    "adapter_id": "adapter-a",
    "adapter_version": "1.0",
    "provider_scope": "sandbox-account",
    "tool_id": "send-message",
    "tool_contract_fingerprint": "a" * 64,
    "capabilities": {
        "idempotency_mode": "provider_enforced",
        "key_scope": "account-operation",
        "idempotency_retention_seconds": 3600,
        "rejects_payload_mismatch": True,
        "concurrent_deduplication": True,
        "supports_outcome_lookup": True,
    },
    "test_suite_version": "v1",
    "sandbox_environment": "provider-sandbox",
}


def signed_envelope():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = {
        "schema": "aibrain-conformance-suite-v1",
        "suite_id": "provider-a-contract-suite",
        "suite_version": "v1",
        "authority_key_id": "authority-1",
        "binding": BINDING,
        "commands": {name: ["/usr/bin/python3", "-m", "suite.tests", name]
                     for name in REQUIRED_CHECKS},
    }
    signature = base64.urlsafe_b64encode(
        private.sign(canonical_json(payload))
    ).decode("ascii").rstrip("=")
    return {"payload": payload, "signature": signature}, public


def verify(envelope, public, binding=BINDING, key_id="authority-1", suite_id="provider-a-contract-suite", suite_version="v1"):
    return verify_signed_suite(
        envelope=envelope,
        authority_public_key=public,
        expected_authority_key_id=key_id,
        expected_suite_id=suite_id,
        expected_suite_version=suite_version,
        expected_binding=binding,
    )


def test_valid_signed_suite_returns_stable_digest_and_commands():
    envelope, public = signed_envelope()
    result = verify(envelope, public)
    assert result["suite_id"] == "provider-a-contract-suite"
    assert result["suite_version"] == "v1"
    assert len(result["suite_sha256"]) == 64
    assert set(result["commands"]) == REQUIRED_CHECKS


def test_unsigned_or_invalid_signature_is_rejected():
    envelope, public = signed_envelope()
    envelope["signature"] = "A" * 86
    with pytest.raises(PermissionError, match="signature verification failed"):
        verify(envelope, public)


def test_modified_command_is_rejected():
    envelope, public = signed_envelope()
    envelope["payload"]["commands"]["lookup_never_dispatches"][-1] = "fake"
    with pytest.raises(PermissionError, match="signature verification failed"):
        verify(envelope, public)


def test_modified_provider_binding_is_rejected():
    envelope, public = signed_envelope()
    envelope["payload"]["binding"]["provider_id"] = "provider-b"
    with pytest.raises(PermissionError, match="signature verification failed"):
        verify(envelope, public)


def test_signed_binding_must_match_expected_binding():
    envelope, public = signed_envelope()
    other = dict(BINDING)
    other["provider_id"] = "provider-b"
    with pytest.raises(PermissionError, match="binding does not match"):
        verify(envelope, public, binding=other)


def test_suite_version_must_match_signed_binding():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = {
        "schema": "aibrain-conformance-suite-v1",
        "suite_id": "provider-a-contract-suite",
        "suite_version": "v2",
        "authority_key_id": "authority-1",
        "binding": BINDING,
        "commands": {name: ["/usr/bin/python3", "-m", "suite.tests", name]
                     for name in REQUIRED_CHECKS},
    }
    envelope = {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(
            private.sign(canonical_json(payload))
        ).decode("ascii").rstrip("="),
    }
    with pytest.raises(PermissionError, match="identity or version"):
        verify(envelope, public)


def test_unknown_suite_fields_and_missing_checks_fail_closed():
    envelope, public = signed_envelope()
    envelope["payload"]["unexpected"] = True
    with pytest.raises(ValueError, match="incomplete or unknown"):
        verify(envelope, public)

    envelope, public = signed_envelope()
    del envelope["payload"]["commands"]["lookup_never_dispatches"]
    with pytest.raises(ValueError, match="exact required"):
        verify(envelope, public)


def test_wrong_authority_id_is_rejected():
    envelope, public = signed_envelope()
    with pytest.raises(PermissionError, match="pinned authority"):
        verify(envelope, public, key_id="other-authority")
