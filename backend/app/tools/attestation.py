"""Ed25519 attestation primitives for trusted conformance runners.

Private keys remain outside AIBrain. This module verifies signatures only;
runner signing happens in the isolated runner or an operator-controlled tool.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ATTESTATION_LIFETIME = timedelta(hours=24)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Attestation payload must be canonical JSON data") from exc


def build_attestation_payload(
    *,
    package_id: str,
    manifest_sha256: str,
    artifact_hashes: dict[str, str],
    runner_id: str,
    provider_id: str,
    adapter_id: str,
    adapter_version: str,
    provider_scope: str,
    sandbox_environment: str,
    nonce: str,
    issued_at: str,
    expires_at: str,
) -> dict:
    payload = {
        "schema": "aibrain-runner-attestation-v1",
        "package_id": package_id,
        "manifest_sha256": manifest_sha256,
        "artifact_hashes": artifact_hashes,
        "runner_id": runner_id,
        "provider_id": provider_id,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "provider_scope": provider_scope,
        "sandbox_environment": sandbox_environment,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    if not isinstance(manifest_sha256, str) or not _SHA256.fullmatch(manifest_sha256):
        raise ValueError("Attestation manifest digest is invalid")
    if not isinstance(artifact_hashes, dict) or not artifact_hashes:
        raise ValueError("Attestation artifact digest set is required")
    if any(
        not isinstance(name, str) or not name
        or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
        for name, digest in artifact_hashes.items()
    ):
        raise ValueError("Attestation artifact digests are invalid")
    for name in (
        "package_id", "runner_id", "provider_id", "adapter_id",
        "adapter_version", "provider_scope", "sandbox_environment",
    ):
        value = payload[name]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"Attestation binding is invalid: {name}")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("Attestation nonce must be 32-128 URL-safe characters")
    issued = _parse_timestamp(issued_at, "issued_at")
    expires = _parse_timestamp(expires_at, "expires_at")
    if expires <= issued or expires - issued > MAX_ATTESTATION_LIFETIME:
        raise ValueError("Attestation lifetime must be positive and at most 24 hours")
    return payload


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"Attestation {field} must be an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"Attestation {field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def sign_attestation_for_runner(
    private_key: Ed25519PrivateKey, payload: dict
) -> str:
    """Runner-side helper; callers must keep private keys outside AIBrain."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("An Ed25519 private key is required")
    return base64.urlsafe_b64encode(
        private_key.sign(canonical_json(payload))
    ).decode("ascii").rstrip("=")


def verify_ed25519_signature(
    public_key: bytes, payload: dict, signature: str
) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("Trusted runner Ed25519 public key must be 32 bytes")
    if not isinstance(signature, str) or not signature or len(signature) > 256:
        raise ValueError("Attestation signature is invalid")
    try:
        raw_signature = base64.b64decode(
            signature + "=" * (-len(signature) % 4),
            altchars=b"-_", validate=True,
        )
        if len(raw_signature) != 64:
            raise ValueError("Attestation signature length is invalid")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            raw_signature, canonical_json(payload)
        )
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise PermissionError("Runner attestation signature verification failed") from exc
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def verify_package_attestation(
    public_key: bytes, payload: dict, signature: str, *,
    package: dict, runner_id: str,
) -> str:
    """Verify signature and every signed package/runner binding."""
    expected = {
        "schema": "aibrain-runner-attestation-v1",
        "package_id": package["id"],
        "manifest_sha256": package["manifest_sha256"],
        "artifact_hashes": package["artifact_hashes"],
        "runner_id": runner_id,
        "provider_id": package["provider_id"],
        "adapter_id": package["adapter_id"],
        "adapter_version": package["adapter_version"],
        "provider_scope": package["provider_scope"],
        "sandbox_environment": package["sandbox_environment"],
    }
    if any(payload.get(name) != value for name, value in expected.items()):
        raise PermissionError("Runner attestation package binding does not match")
    return verify_ed25519_signature(public_key, payload, signature)


def generate_test_keypair() -> tuple[bytes, Ed25519PrivateKey]:
    """Test utility only; production runner keys must be generated externally."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return public_key, private_key
