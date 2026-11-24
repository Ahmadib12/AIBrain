import base64
import hashlib
import json
import os
import sys
import time
import time
from pathlib import Path

import pytest

from backend.app.tools.conformance import REQUIRED_CHECKS, verify_evidence_manifest
from scripts.conformance_runner import run_suite
from backend.app.tools.conformance import canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


BINDING = {
    "provider_id": "provider-sandbox",
    "adapter_id": "sample-adapter",
    "adapter_version": "1.0.0",
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
    "test_suite_version": "suite-1",
    "sandbox_environment": "isolated-test",
}


def commands_for(code="pass"):
    script = (
        "import sys; "
        + ("sys.exit(0)" if code == "pass" else
           "sys.exit(7)" if code == "fail" else
           "import time; time.sleep(5)")
    )
    return {name: [sys.executable, "-c", script] for name in REQUIRED_CHECKS}



def signed_suite(binding, commands):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = {
        "schema": "aibrain-conformance-suite-v1",
        "suite_id": "provider-x-safety-suite",
        "suite_version": binding["test_suite_version"],
        "authority_key_id": "suite-authority-1",
        "binding": binding,
        "commands": commands,
    }
    envelope = {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(private.sign(canonical_json(payload))).decode("ascii").rstrip("="),
    }
    return envelope, public


def execute(binding, commands, output_dir, **kwargs):
    envelope, public = signed_suite(binding, commands)
    return run_suite(
        suite_envelope=envelope,
        authority_public_key=public,
        authority_key_id="suite-authority-1",
        output_dir=output_dir,
        **kwargs,
    )

def test_runner_executes_exact_suite_and_builds_verifiable_manifest(tmp_path):
    output = tmp_path / "artifacts"
    result = execute(BINDING, commands_for(), output)
    assert result["status"] == "passed"
    assert set(result["results"]) == REQUIRED_CHECKS
    manifest = json.loads((output / "manifest.json").read_text())
    artifacts = {
        name: (output / name).read_bytes()
        for name in manifest["artifacts"]
    }
    verified = verify_evidence_manifest(manifest, artifacts)
    assert len(verified["conformance_results"]) == 10


def test_failed_child_is_recorded_and_no_certifiable_manifest_is_created(tmp_path):
    commands = commands_for()
    commands[sorted(REQUIRED_CHECKS)[0]] = [sys.executable, "-c", "raise SystemExit(7)"]
    output = tmp_path / "artifacts"
    result = execute(BINDING, commands, output)
    assert result["status"] == "incomplete"
    assert result["results"][sorted(REQUIRED_CHECKS)[0]]["status"] == "failed"
    assert result["manifest"] is None
    assert not (output / "manifest.json").exists()


def test_timeout_is_unknown_and_never_passes(tmp_path):
    commands = commands_for()
    commands[sorted(REQUIRED_CHECKS)[0]] = [
        sys.executable, "-c", "import time; time.sleep(10)"
    ]
    output = tmp_path / "artifacts"
    result = execute(
        BINDING, commands, output,
        timeout_seconds=1,
    )
    assert result["status"] == "incomplete"
    assert result["results"][sorted(REQUIRED_CHECKS)[0]]["status"] == "unknown"
    assert result["manifest"] is None


def test_missing_check_command_is_rejected(tmp_path):
    commands = commands_for()
    commands.pop(sorted(REQUIRED_CHECKS)[0])
    with pytest.raises(ValueError, match="exact required checks"):
        execute(BINDING, commands, tmp_path / "out")


def test_shell_string_is_not_accepted_as_command(tmp_path):
    commands = commands_for()
    commands[sorted(REQUIRED_CHECKS)[0]] = "echo unsafe"
    with pytest.raises(ValueError, match="Invalid argv"):
        execute(BINDING, commands, tmp_path / "out")


def test_nonempty_output_directory_is_rejected(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "forged.log").write_text("forged")
    with pytest.raises(ValueError, match="must be empty"):
        execute(BINDING, commands_for(), output)


def test_runner_does_not_inherit_parent_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("AIBRAIN_RUNNER_PRIVATE_KEY_B64", "secret-value")
    marker = tmp_path / "secret.txt"
    script = (
        "import os,pathlib; "
        f"pathlib.Path({str(marker)!r}).write_text(os.getenv('AIBRAIN_RUNNER_PRIVATE_KEY_B64','missing'))"
    )
    commands = {name: [sys.executable, "-c", script] for name in REQUIRED_CHECKS}
    result = execute(BINDING, commands, tmp_path / "out")
    assert result["status"] == "passed"
    assert marker.read_text() == "missing"


def test_manifest_builder_rejects_invalid_binding(tmp_path):
    binding = dict(BINDING)
    binding["tool_contract_fingerprint"] = "not-a-digest"
    with pytest.raises(ValueError, match="fingerprint"):
        execute(binding, commands_for(), tmp_path / "out")



def test_process_that_cannot_start_is_not_run_and_not_certifiable(tmp_path):
    commands = commands_for()
    commands[sorted(REQUIRED_CHECKS)[0]] = ["/definitely/not/a/real/executable"]
    output = tmp_path / "out"
    result = execute(BINDING, commands, output)
    assert result["status"] == "incomplete"
    assert result["results"][sorted(REQUIRED_CHECKS)[0]]["status"] == "not_run"
    assert result["manifest"] is None


def test_output_flood_is_bounded_by_child_file_size_limit(tmp_path):
    commands = commands_for()
    commands[sorted(REQUIRED_CHECKS)[0]] = [
        sys.executable, "-c", "import sys; sys.stdout.write('x' * 2_000_000)"
    ]
    output = tmp_path / "out"
    result = execute(BINDING, commands, output)
    assert result["status"] == "incomplete"
    assert result["results"][sorted(REQUIRED_CHECKS)[0]]["status"] == "failed"
    assert (output / f"{sorted(REQUIRED_CHECKS)[0]}.log").stat().st_size <= 256 * 1024


def test_invalid_capability_claims_rejected_before_execution(tmp_path):
    binding = dict(BINDING)
    binding["capabilities"] = dict(BINDING["capabilities"])
    binding["capabilities"]["supports_outcome_lookup"] = "yes"
    with pytest.raises(ValueError, match="must be boolean"):
        execute(binding, commands_for(), tmp_path / "out")



@pytest.mark.skipif(os.name != "posix", reason="Process-group cleanup requires POSIX")
def test_runner_kills_descendants_after_command_parent_exits(tmp_path):
    marker = tmp_path / "descendant-survived"
    child_code = (
        "import time,pathlib; time.sleep(0.5); "
        f"pathlib.Path({str(marker)!r}).write_text('alive')"
    )
    child_script = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}])"
    )
    commands = commands_for()
    commands[sorted(REQUIRED_CHECKS)[0]] = [sys.executable, "-c", child_script]
    result = execute(BINDING, commands, tmp_path / "out")
    assert result["status"] == "passed"
    time.sleep(0.7)
    assert not marker.exists()


def test_unsigned_suite_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="signed conformance suite"):
        run_suite(
            suite_envelope={"payload": {"binding": BINDING}, "signature": ""},
            authority_public_key=b"x" * 32,
            authority_key_id="suite-authority-1",
            output_dir=tmp_path / "out",
        )


def test_command_substitution_invalidates_suite_signature(tmp_path):
    envelope, public = signed_suite(BINDING, commands_for())
    envelope["payload"]["commands"][sorted(REQUIRED_CHECKS)[0]] = [
        sys.executable, "-c", "pass"
    ]
    with pytest.raises(PermissionError, match="signature verification failed"):
        run_suite(
            suite_envelope=envelope,
            authority_public_key=public,
            authority_key_id="suite-authority-1",
            output_dir=tmp_path / "out",
        )


def test_wrong_suite_authority_key_id_is_rejected(tmp_path):
    envelope, public = signed_suite(BINDING, commands_for())
    with pytest.raises(PermissionError, match="pinned authority"):
        run_suite(
            suite_envelope=envelope,
            authority_public_key=public,
            authority_key_id="attacker-key",
            output_dir=tmp_path / "out",
        )


def test_signed_suite_digest_and_commands_are_recorded(tmp_path):
    envelope, public = signed_suite(BINDING, commands_for())
    output = tmp_path / "out"
    result = run_suite(
        suite_envelope=envelope, authority_public_key=public,
        authority_key_id="suite-authority-1", output_dir=output,
    )
    report = json.loads((output / result["report"]).read_text())
    expected = hashlib.sha256(canonical_json(envelope["payload"])).hexdigest()
    assert report["suite_sha256"] == expected
    assert report["suite_authority_key_id"] == "suite-authority-1"
    assert set(report["command_sha256"]) == REQUIRED_CHECKS
    assert "signed-suite.json" in json.loads((output / "manifest.json").read_text())["artifacts"]
