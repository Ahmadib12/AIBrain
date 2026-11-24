import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from scripts.submit_conformance_evidence import (
    canonical_json,
    load_evidence,
    submit_evidence,
)


def test_runner_loads_only_declared_artifact_bytes(tmp_path: Path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    content = b"actual sandbox output"
    (artifact_dir / "report.bin").write_bytes(content)
    manifest = {
        "artifacts": {"report.bin": hashlib.sha256(content).hexdigest()}
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded_manifest, artifacts = load_evidence(manifest_path, artifact_dir)

    assert loaded_manifest == manifest
    assert artifacts == {"report.bin": content}


def test_runner_rejects_modified_artifact_before_upload(tmp_path: Path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "report.bin").write_bytes(b"modified")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"artifacts": {"report.bin": "a" * 64}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="digest mismatch"):
        load_evidence(manifest_path, artifact_dir)


def test_runner_signs_payload_locally_and_never_sends_private_key(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    now = datetime.now(timezone.utc)
    calls = []
    signed_payload = {
        "schema": "aibrain-runner-attestation-v1",
        "package_id": "package-123",
        "manifest_sha256": "c" * 64,
        "artifact_hashes": {"report.bin": "d" * 64},
        "runner_id": "isolated-runner",
        "provider_id": "provider-a",
        "adapter_id": "adapter-a",
        "adapter_version": "1.0",
        "provider_scope": "sandbox",
        "sandbox_environment": "isolated-ci",
        "nonce": "nonce_" + "x" * 32,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }

    def fake_post_json(base_url, path, token, payload):
        calls.append((path, token, payload))
        if path.endswith("/runner/evidence"):
            return {
                "package_id": "package-123",
                "manifest_sha256": "c" * 64,
                "expires_at": (now + timedelta(days=1)).isoformat(),
            }
        if path.endswith("/attestation-payload"):
            # The client generates the nonce and timestamps for each run.
            # The server signs exactly the values the client requested.
            signed_payload["nonce"] = payload["nonce"]
            signed_payload["issued_at"] = payload["issued_at"]
            signed_payload["expires_at"] = payload["expires_at"]
            assert payload["key_id"] == "trusted-key"
            assert payload["runner_id"] == "isolated-runner"
            return signed_payload
        if path.endswith("/attest"):
            assert payload["nonce"] == signed_payload["nonce"]
            assert payload["key_id"] == "trusted-key"
            signature = base64.urlsafe_b64decode(
                payload["signature"] + "=" * (-len(payload["signature"]) % 4)
            )
            public_key.verify(signature, canonical_json(signed_payload))
            assert "private_key" not in payload
            return {
                "package_id": "package-123",
                "payload_sha256": "e" * 64,
                "runner_id": "isolated-runner",
            }
        raise AssertionError(f"Unexpected runner API path: {path}")

    monkeypatch.setattr(
        "scripts.submit_conformance_evidence.post_json", fake_post_json
    )
    result = submit_evidence(
        base_url="https://aibrain.example",
        runner_token="r" * 40,
        private_key_b64=base64.b64encode(private_bytes).decode("ascii"),
        key_id="trusted-key",
        runner_id="isolated-runner",
        manifest={"artifacts": {"report.bin": "d" * 64}},
        artifacts={"report.bin": b"test artifact"},
    )

    assert result == {
        "package_id": "package-123",
        "manifest_sha256": "c" * 64,
        "attestation_payload_sha256": "e" * 64,
        "runner_id": "isolated-runner",
        "provenance": "runner_attested",
    }
    assert len(calls) == 3
    assert all(call[1] == "r" * 40 for call in calls)
    assert all("private_key" not in call[2] for call in calls)


def test_runner_rejects_non_https_remote_endpoint():
    from scripts.submit_conformance_evidence import _api_url

    with pytest.raises(ValueError, match="HTTPS"):
        _api_url("http://aibrain.example", "/api/v1/tools/runner/evidence")
