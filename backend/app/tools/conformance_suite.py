"""Verification of independently signed, provider-bound conformance suites."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from backend.app.tools.conformance import REQUIRED_CHECKS, canonical_json

_SUITE_SCHEMA = "aibrain-conformance-suite-v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def verify_signed_suite(
    *,
    envelope: dict[str, Any],
    authority_public_key: bytes,
    expected_authority_key_id: str,
    expected_suite_id: str,
    expected_suite_version: str,
    expected_binding: dict[str, Any],
) -> dict[str, Any]:
    """Verify authority signature, exact suite schema, binding and command map."""
    if not isinstance(authority_public_key, bytes) or len(authority_public_key) != 32:
        raise ValueError("Suite authority Ed25519 public key must be 32 bytes")
    if not isinstance(expected_authority_key_id, str) or not expected_authority_key_id.strip():
        raise ValueError("Pinned suite authority key ID is required")
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("Signed suite envelope fields are invalid")
    payload, signature = envelope["payload"], envelope["signature"]
    required = {
        "schema", "suite_id", "suite_version", "authority_key_id",
        "binding", "commands",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("Signed suite payload fields are incomplete or unknown")
    if payload["schema"] != _SUITE_SCHEMA:
        raise ValueError("Unsupported conformance suite schema")
    for field in ("suite_id", "suite_version", "authority_key_id"):
        value = payload[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"Invalid signed suite field: {field}")
    if payload["authority_key_id"] != expected_authority_key_id:
        raise PermissionError("Suite was not signed by the pinned authority key")
    if payload["suite_id"] != expected_suite_id or payload["suite_version"] != expected_suite_version:
        raise PermissionError("Conformance suite identity or version is not deployment-approved")
    if payload["suite_version"] != expected_binding.get("test_suite_version"):
        raise PermissionError("Signed suite version does not match evidence binding")
    if payload["binding"] != expected_binding:
        raise PermissionError("Signed suite provider/tool binding does not match")
    commands = payload["commands"]
    if not isinstance(commands, dict) or set(commands) != REQUIRED_CHECKS:
        raise ValueError("Signed suite must define the exact required conformance checks")
    for check_id, argv in commands.items():
        if (
            not isinstance(argv, list) or not argv or len(argv) > 64
            or any(
                not isinstance(part, str) or not part or len(part) > 4096 or "\x00" in part
                for part in argv
            )
            or sum(len(part.encode("utf-8")) for part in argv if isinstance(part, str)) > 16384
        ):
            raise ValueError(f"Invalid signed command for conformance check: {check_id}")
    if not isinstance(signature, str) or not signature or len(signature) > 256:
        raise ValueError("Suite authority signature is invalid")
    try:
        raw = base64.b64decode(
            signature + "=" * (-len(signature) % 4),
            altchars=b"-_", validate=True,
        )
        if len(raw) != 64:
            raise ValueError("Suite authority signature length is invalid")
        Ed25519PublicKey.from_public_bytes(authority_public_key).verify(
            raw, canonical_json(payload)
        )
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise PermissionError("Conformance suite authority signature verification failed") from exc
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    if not _SHA256.fullmatch(digest):
        raise ValueError("Signed suite digest is invalid")
    return {
        "suite_id": payload["suite_id"],
        "suite_version": payload["suite_version"],
        "authority_key_id": payload["authority_key_id"],
        "suite_sha256": digest,
        "commands": {key: list(value) for key, value in commands.items()},
    }
