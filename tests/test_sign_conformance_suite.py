import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from backend.app.tools.conformance import REQUIRED_CHECKS
from backend.app.tools.conformance_suite import verify_signed_suite
from scripts.sign_conformance_suite import sign_payload


def test_offline_signer_produces_suite_verifiable_by_pinned_public_key():
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes_raw()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
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
    payload = {
        "schema": "aibrain-conformance-suite-v1",
        "suite_id": "suite",
        "suite_version": "v1",
        "authority_key_id": "authority",
        "binding": binding,
        "commands": {name: ["/opt/tests/run-check", name] for name in REQUIRED_CHECKS},
    }
    envelope = sign_payload(payload, base64.b64encode(raw_private).decode("ascii"))
    verified = verify_signed_suite(
        envelope=envelope,
        authority_public_key=public,
        expected_authority_key_id="authority",
        expected_binding=binding,
    )
    assert verified["suite_id"] == "suite"
    assert len(verified["suite_sha256"]) == 64
