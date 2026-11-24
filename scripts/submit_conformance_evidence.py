"""Submit a completed conformance evidence package from an isolated runner.

This client transports already-generated evidence and signs AIBrain's canonical
attestation payload locally. It does not generate evidence or run provider tests.
Keep AIBRAIN_RUNNER_PRIVATE_KEY_B64 only in the isolated runner's secret store.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def load_evidence(manifest_path: Path, artifact_dir: Path) -> tuple[dict, dict[str, bytes]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifacts"), dict):
        raise ValueError("Manifest must contain an artifact digest mapping")
    declared = manifest["artifacts"]
    if not declared or len(declared) > MAX_ARTIFACTS:
        raise ValueError("Manifest artifact count is outside allowed limits")

    root = artifact_dir.resolve(strict=True)
    artifacts: dict[str, bytes] = {}
    total = 0
    for name, expected_digest in declared.items():
        if (
            not isinstance(name, str) or not name or name in (".", "..")
            or "/" in name or "\\" in name or "\x00" in name
        ):
            raise ValueError("Manifest contains an unsafe artifact name")
        path = (root / name).resolve(strict=True)
        if path.parent != root or not path.is_file():
            raise ValueError("Artifact path escapes the configured artifact directory")
        content = path.read_bytes()
        if not content or len(content) > MAX_ARTIFACT_BYTES:
            raise ValueError("Artifact is empty or exceeds the per-file size limit")
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected_digest:
            raise ValueError(f"Artifact digest mismatch: {name}")
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Evidence package exceeds the total artifact size limit")
        artifacts[name] = content
    return manifest, artifacts


def _api_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A valid AIBrain API base URL is required")
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
        raise ValueError("Runner evidence may only be sent over HTTPS")
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def post_json(base_url: str, path: str, token: str, payload: dict) -> dict:
    request = Request(
        _api_url(base_url, path),
        data=canonical_json(payload),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-AIBrain-Runner-Token": token,
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"AIBrain runner API returned HTTP {exc.code}") from None
    except URLError:
        raise RuntimeError("Could not reach the AIBrain runner API") from None
    if not isinstance(parsed, dict):
        raise RuntimeError("AIBrain runner API returned an invalid response")
    return parsed


def submit_evidence(
    *,
    base_url: str,
    runner_token: str,
    private_key_b64: str,
    key_id: str,
    runner_id: str,
    manifest: dict,
    artifacts: dict[str, bytes],
) -> dict:
    try:
        private_bytes = base64.b64decode(private_key_b64, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Runner private key must be base64-encoded raw Ed25519 bytes") from None
    if len(private_bytes) != 32:
        raise ValueError("Runner private key must decode to exactly 32 bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    uploaded = post_json(
        base_url,
        "/api/v1/tools/runner/evidence",
        runner_token,
        {
            "manifest": manifest,
            "artifacts_base64": {
                name: base64.b64encode(content).decode("ascii")
                for name, content in artifacts.items()
            },
        },
    )
    package_id = uploaded.get("package_id")
    if not isinstance(package_id, str) or not package_id:
        raise RuntimeError("AIBrain did not return an evidence package ID")

    issued_at = datetime.now(timezone.utc)
    package_expiry = datetime.fromisoformat(
        uploaded["expires_at"].replace("Z", "+00:00")
    )
    expires_at = min(issued_at + timedelta(hours=12), package_expiry)
    if expires_at <= issued_at:
        raise RuntimeError("Evidence package is already expired")

    nonce = secrets.token_urlsafe(32)
    issued_text = issued_at.isoformat()
    expiry_text = expires_at.isoformat()
    payload = post_json(
        base_url,
        f"/api/v1/tools/runner/evidence/{package_id}/attestation-payload",
        runner_token,
        {
            "key_id": key_id,
            "runner_id": runner_id,
            "nonce": nonce,
            "issued_at": issued_text,
            "expires_at": expiry_text,
        },
    )
    signature = base64.urlsafe_b64encode(
        private_key.sign(canonical_json(payload))
    ).decode("ascii").rstrip("=")
    attested = post_json(
        base_url,
        f"/api/v1/tools/runner/evidence/{package_id}/attest",
        runner_token,
        {
            "key_id": key_id,
            "runner_id": runner_id,
            "nonce": nonce,
            "issued_at": issued_text,
            "expires_at": expiry_text,
            "signature": signature,
        },
    )
    return {
        "package_id": package_id,
        "manifest_sha256": uploaded.get("manifest_sha256"),
        "attestation_payload_sha256": attested.get("payload_sha256"),
        "runner_id": runner_id,
        "provenance": "runner_attested",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-base-url", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--runner-id", required=True)
    args = parser.parse_args()

    runner_token = os.environ.get("AIBRAIN_RUNNER_INGEST_TOKEN", "")
    private_key_b64 = os.environ.get("AIBRAIN_RUNNER_PRIVATE_KEY_B64", "")
    if len(runner_token) < 32 or not private_key_b64:
        print(
            "AIBRAIN_RUNNER_INGEST_TOKEN and AIBRAIN_RUNNER_PRIVATE_KEY_B64 "
            "must be configured in the isolated runner secret store.",
            file=sys.stderr,
        )
        return 2
    try:
        manifest, artifacts = load_evidence(args.manifest, args.artifact_dir)
        result = submit_evidence(
            base_url=args.api_base_url,
            runner_token=runner_token,
            private_key_b64=private_key_b64,
            key_id=args.key_id,
            runner_id=args.runner_id,
            manifest=manifest,
            artifacts=artifacts,
        )
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f"Evidence submission failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
