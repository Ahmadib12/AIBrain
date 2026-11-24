"""Generate an encrypted Ed25519 conformance-suite authority key pair locally.

The private key is written as encrypted PKCS#8 PEM with restrictive file
permissions. Only the public key is printed. Never run this in the repository
or a shared/production API environment.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_keypair(private_path: Path, public_path: Path, passphrase: str) -> dict[str, str]:
    if len(passphrase) < 16:
        raise ValueError("Use a passphrase of at least 16 characters")
    if private_path.exists() or public_path.exists():
        raise FileExistsError("Key output already exists; refusing to overwrite")
    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(private_path.parent, 0o700)
    except OSError:
        pass

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_b64 = base64.b64encode(public_raw).decode("ascii")
    fingerprint = hashlib.sha256(public_raw).hexdigest()

    # Exclusive creation prevents accidental replacement and follows symlinks
    # only if they already existed (which is rejected above).
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(private_pem)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    try:
        os.chmod(private_path, 0o600)
        with public_path.open("x", encoding="ascii") as stream:
            stream.write(public_b64 + "\\n")
        os.chmod(public_path, 0o644)
    except Exception:
        private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise
    return {"public_key_b64": public_b64, "fingerprint_sha256": fingerprint}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-key",
        type=Path,
        default=Path.home() / ".config/aibrain/keys/conformance-suite-authority.pem",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=Path.home() / ".config/aibrain/keys/conformance-suite-authority.pub",
    )
    args = parser.parse_args()
    try:
        first = getpass.getpass("Create private-key passphrase (minimum 16 characters): ")
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise ValueError("Passphrases do not match")
        result = generate_keypair(args.private_key, args.public_key, first)
    except (OSError, ValueError) as exc:
        print(f"Key generation failed: {exc}", file=sys.stderr)
        return 2

    print("Ed25519 suite-authority key pair created.")
    print(f"Private key: {args.private_key} (encrypted; mode 0600)")
    print(f"Public key:  {args.public_key}")
    print(f"Public-key SHA-256 fingerprint: {result['fingerprint_sha256']}")
    print(f"AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64={result['public_key_b64']}")
    print("Set the authority key ID and approved suite ID/version separately.")
    print("Do not commit or upload the private key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
