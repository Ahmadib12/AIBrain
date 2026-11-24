"""Offline signing utility for reviewed conformance-suite payloads.

Run only in the isolated suite-authority environment. Never copy the private
key to the conformance runner or AIBrain server.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.app.tools.conformance import canonical_json


def sign_payload(payload: dict, private_key_b64: str) -> dict:
    try:
        raw = base64.b64decode(private_key_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Suite authority private key encoding is invalid") from exc
    if len(raw) != 32:
        raise ValueError("Suite authority Ed25519 private key must be 32 bytes")
    if not isinstance(payload, dict):
        raise ValueError("Suite payload must be a JSON object")
    signature = Ed25519PrivateKey.from_private_bytes(raw).sign(canonical_json(payload))
    return {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        private_key_b64 = os.environ.get("AIBRAIN_SUITE_AUTHORITY_PRIVATE_KEY_B64", "")
        if not private_key_b64:
            raise ValueError("Offline suite-authority private key is not provisioned")
        payload = json.loads(args.payload.read_text(encoding="utf-8"))
        envelope = sign_payload(payload, private_key_b64)
        args.output.write_bytes(canonical_json(envelope))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Suite signing failed: {exc}", file=sys.stderr)
        return 2
    print("Signed conformance suite written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
