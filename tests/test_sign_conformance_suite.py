import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from backend.app.tools.conformance import REQUIRED_CHECKS
from backend.app.tools.conformance_suite import verify_signed_suite
from scripts.generate_conformance_suite_authority import generate_keypair
from scripts.sign_conformance_suite import sign_payload, sign_payload_with_pem


def _payload():
    binding = {
        "provider_id": "provider",
        "adapter_id": "adapter",
        "adapter_version": "1",
        "provider_scope": "sandbox",
        "tool_id": "tool",
        "tool_contract_fingerprint": "a" * 64,
        "capabilities": {
            "idempotency_mode": "none",
            "key_scope": None,
            "idempotency_retention_seconds": None,
            "rejects_payload_mismatch": False,
            "concurrent_deduplication": False,
            "supports_outcome_lookup": False,
        },
        "test_suite_version": "v1",
        "sandbox_environment": "isolated",
    }
    return {
        "schema": "aibrain-conformance-suite-v1",
        "suite_id": "suite",
        "suite_version": "v1",
        "authority_key_id": "authority",
        "binding": binding,
        "commands": {name: ["/opt/tests/run-check", name] for name in REQUIRED_CHECKS},
    }, binding


def test_offline_signer_produces_suite_verifiable_by_pinned_public_key():
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes_raw()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload, binding = _payload()
    envelope = sign_payload(payload, base64.b64encode(raw_private).decode("ascii"))
    verified = verify_signed_suite(
        envelope=envelope,
        authority_public_key=public,
        expected_authority_key_id="authority",
        expected_suite_id="suite",
        expected_suite_version="v1",
        expected_binding=binding,
    )
    assert verified["suite_id"] == "suite"
    assert len(verified["suite_sha256"]) == 64


def test_key_generator_writes_encrypted_private_key_and_public_key(tmp_path):
    private_path = tmp_path / "keys" / "authority.pem"
    public_path = tmp_path / "keys" / "authority.pub"
    result = generate_keypair(private_path, public_path, "a-long-test-passphrase")
    assert private_path.stat().st_mode & 0o777 == 0o600
    assert public_path.read_text().strip() == result["public_key_b64"]
    assert b"ENCRYPTED" in private_path.read_bytes()
    payload, binding = _payload()
    envelope = sign_payload_with_pem(payload, private_path, "a-long-test-passphrase")
    public = base64.b64decode(result["public_key_b64"])
    verified = verify_signed_suite(
        envelope=envelope,
        authority_public_key=public,
        expected_authority_key_id="authority",
        expected_suite_id="suite",
        expected_suite_version="v1",
        expected_binding=binding,
    )
    assert verified["suite_id"] == "suite"


def test_key_generator_refuses_overwrite(tmp_path):
    private_path = tmp_path / "authority.pem"
    public_path = tmp_path / "authority.pub"
    generate_keypair(private_path, public_path, "a-long-test-passphrase")
    with pytest.raises(FileExistsError):
        generate_keypair(private_path, public_path, "another-long-passphrase")


def test_key_generator_rejects_short_passphrase(tmp_path):
    with pytest.raises(ValueError, match="16 characters"):
        generate_keypair(tmp_path / "authority.pem", tmp_path / "authority.pub", "short")
