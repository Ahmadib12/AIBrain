"""Offline signing utility for reviewed conformance-suite payloads.

Run only in the isolated suite-authority environment. Never copy the private
key to the conformance runner or AIBrain server. The CLI reads an encrypted
PKCS#8 PEM key from a local file and prompts for its passphrase.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.app.tools.conformance import canonical_json


def sign_payload(payload: dict, private_key_b64: str) -> dict:
    """Compatibility helper for in-memory tests; never use env vars for CLI keys."""
    try:
        raw = base64.b64decode(private_key_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Suite authority private key encoding is invalid") from exc
    if len(raw) != 32:
        raise ValueError("Suite authority Ed25519 private key must be 32 bytes")
    return _sign(payload, Ed25519PrivateKey.from_private_bytes(raw))


def _sign(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Suite payload must be a JSON object")
    signature = private_key.sign(canonical_json(payload))
    return {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def sign_payload_with_pem(payload: dict, private_key_path: Path, passphrase: str) -> dict:
    try:
        key = serialization.load_pem_private_key(
            private_key_path.read_bytes(), password=passphrase.encode("utf-8")
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("Unable to unlock suite-authority private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Suite-authority key must be Ed25519")
    return _sign(payload, key)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--private-key-file", type=Path,
        default=Path.home() / ".config/aibrain/keys/conformance-suite-authority.pem",
    )
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("Output already exists; choose a new path to avoid overwriting")
        passphrase = getpass.getpass("Suite-authority private-key passphrase: ")
        if not passphrase:
            raise ValueError("Private-key passphrase cannot be empty")
        payload = json.loads(args.payload.read_text(encoding="utf-8"))
        envelope = sign_payload_with_pem(payload, args.private_key_file, passphrase)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("xb") as stream:
            stream.write(canonical_json(envelope))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Suite signing failed: {exc}", file=sys.stderr)
        return 2
    print("Signed conformance suite written. Private key was not exported.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
