import json
import sys
from pathlib import Path

from scripts import run_and_attest_conformance as workflow


def _write_inputs(tmp_path):
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"payload": {"binding": {}}, "signature": "signature"}))
    return suite


def test_workflow_never_reads_or_submits_credentials_after_incomplete_run(
    tmp_path, monkeypatch, capsys
):
    suite = _write_inputs(tmp_path)
    calls = []

    def fake_run_suite(**kwargs):
        calls.append("run")
        return {
            "status": "incomplete",
            "report": "execution-report.json",
            "manifest": None,
        }

    def forbidden(*args, **kwargs):
        raise AssertionError("Evidence loading/submission must not occur after failure")

    monkeypatch.setenv("AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64", "cHVibGlj")
    monkeypatch.setattr(workflow, "run_suite", fake_run_suite)
    monkeypatch.setattr(workflow, "load_evidence", forbidden)
    monkeypatch.setattr(workflow, "submit_evidence", forbidden)
    monkeypatch.setattr(sys, "argv", [
        "run_and_attest_conformance",
        "--suite", str(suite),
        "--authority-key-id", "suite-authority-1",
        "--output-dir", str(tmp_path / "out"),
        "--api-base-url", "https://aibrain.example",
        "--key-id", "runner-key",
        "--runner-id", "runner-1",
    ])

    assert workflow.main() == 1
    assert calls == ["run"]
    assert '"status": "incomplete"' in capsys.readouterr().out


def test_workflow_submits_only_runner_generated_manifest_after_full_pass(
    tmp_path, monkeypatch, capsys
):
    binding, commands = _write_inputs(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    calls = []

    def fake_run_suite(**kwargs):
        calls.append("run")
        (output / "manifest.json").write_text('{"artifacts":{"run.log":"digest"}}')
        return {
            "status": "passed",
            "report": "execution-report.json",
            "manifest": "manifest.json",
        }

    manifest = {"artifacts": {"run.log": "digest"}}
    artifacts = {"run.log": b"actual run output"}

    def fake_load_evidence(manifest_path, artifact_dir):
        calls.append(("load", manifest_path, artifact_dir))
        return manifest, artifacts

    def fake_submit(**kwargs):
        calls.append(("submit", kwargs))
        return {
            "package_id": "pkg-1",
            "manifest_sha256": "a" * 64,
            "attestation_payload_sha256": "b" * 64,
            "runner_id": "runner-1",
            "provenance": "runner_attested",
        }

    monkeypatch.setattr(workflow, "run_suite", fake_run_suite)
    monkeypatch.setattr(workflow, "load_evidence", fake_load_evidence)
    monkeypatch.setattr(workflow, "submit_evidence", fake_submit)
    monkeypatch.setenv("AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64", "cHVibGlj")
    monkeypatch.setenv("AIBRAIN_TRUSTED_RUNNER_INGEST_TOKEN", "t" * 40)
    monkeypatch.setenv("AIBRAIN_RUNNER_PRIVATE_KEY_B64", "base64-key-material")
    monkeypatch.setattr(sys, "argv", [
        "run_and_attest_conformance",
        "--suite", str(suite),
        "--authority-key-id", "suite-authority-1",
        "--output-dir", str(output),
        "--api-base-url", "https://aibrain.example",
        "--key-id", "runner-key",
        "--runner-id", "runner-1",
    ])

    assert workflow.main() == 0
    assert calls[0] == "run"
    assert calls[1][0] == "load"
    assert calls[2][0] == "submit"
    submitted = calls[2][1]
    assert submitted["manifest"] is manifest
    assert submitted["artifacts"] is artifacts
    assert submitted["runner_token"] == "t" * 40
    assert submitted["private_key_b64"] == "base64-key-material"
    assert '"status": "attested"' in capsys.readouterr().out
