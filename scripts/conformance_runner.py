"""Provider-neutral, bounded conformance-suite process runner.

This is a process supervisor, not a complete OS/container sandbox. Run it inside
an independently hardened runner VM/container with network policy enforced
outside this process. It deliberately never inherits runner/API/private-key
secrets from the parent environment.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.app.tools.conformance import (
    REQUIRED_CHECKS, canonical_json, verify_evidence_manifest,
)
from backend.app.tools.conformance_suite import verify_signed_suite

MAX_COMMANDS = 64
MAX_OUTPUT_BYTES = 256 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300
MAX_MEMORY_MB = 1024
MAX_CPU_SECONDS = 300
BINDING_FIELDS = {
    "provider_id", "adapter_id", "adapter_version", "provider_scope",
    "tool_id", "tool_contract_fingerprint", "capabilities",
    "test_suite_version", "sandbox_environment",
}


def _load_json(path: Path) -> dict:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Signed suite file exceeds the 1 MiB limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _validate_commands(commands: dict[str, Any]) -> dict[str, list[str]]:
    if set(commands) != set(REQUIRED_CHECKS):
        missing = sorted(REQUIRED_CHECKS - set(commands))
        extra = sorted(set(commands) - REQUIRED_CHECKS)
        raise ValueError(f"Command map must cover exact required checks; missing={missing}, extra={extra}")
    normalized: dict[str, list[str]] = {}
    for check_id, argv in commands.items():
        if (
            not isinstance(argv, list) or not argv or len(argv) > MAX_COMMANDS
            or any(not isinstance(part, str) or not part or "\x00" in part for part in argv)
        ):
            raise ValueError(f"Invalid argv for conformance check: {check_id}")
        normalized[check_id] = list(argv)
    return normalized


def _validate_binding(binding: dict) -> None:
    if set(binding) != BINDING_FIELDS:
        raise ValueError("Binding file must contain the exact evidence binding fields")
    for field in (
        "provider_id", "adapter_id", "adapter_version", "provider_scope",
        "tool_id", "test_suite_version", "sandbox_environment",
    ):
        value = binding[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"Invalid evidence binding: {field}")
    fingerprint = binding["tool_contract_fingerprint"]
    if (
        not isinstance(fingerprint, str) or len(fingerprint) != 64
        or any(c not in "0123456789abcdef" for c in fingerprint)
    ):
        raise ValueError("Invalid tool contract fingerprint")
    capabilities = binding["capabilities"]
    expected = {
        "idempotency_mode", "key_scope", "idempotency_retention_seconds",
        "rejects_payload_mismatch", "concurrent_deduplication",
        "supports_outcome_lookup",
    }
    if not isinstance(capabilities, dict) or set(capabilities) != expected:
        raise ValueError("A complete provider capability snapshot is required")
    for field in (
        "rejects_payload_mismatch", "concurrent_deduplication",
        "supports_outcome_lookup",
    ):
        if not isinstance(capabilities[field], bool):
            raise ValueError(f"Capability {field} must be boolean")
    if capabilities["idempotency_mode"] == "provider_enforced":
        if (
            not isinstance(capabilities["key_scope"], str)
            or not capabilities["key_scope"].strip()
            or isinstance(capabilities["idempotency_retention_seconds"], bool)
            or not isinstance(capabilities["idempotency_retention_seconds"], int)
            or capabilities["idempotency_retention_seconds"] <= 0
            or capabilities["rejects_payload_mismatch"] is not True
            or capabilities["concurrent_deduplication"] is not True
        ):
            raise ValueError("Provider-enforced capability snapshot is incomplete")
    elif capabilities["idempotency_mode"] == "none":
        if (
            capabilities["key_scope"] is not None
            or capabilities["idempotency_retention_seconds"] is not None
            or capabilities["rejects_payload_mismatch"] is True
            or capabilities["concurrent_deduplication"] is True
        ):
            raise ValueError("Non-idempotent capability snapshot cannot claim deduplication")
    else:
        raise ValueError("Unsupported capability idempotency mode")


def _resource_limiter(memory_mb: int, cpu_seconds: int):
    """Return a POSIX pre-exec limiter; unsupported platforms fail closed."""
    if os.name != "posix":
        raise RuntimeError("This runner requires POSIX resource limits")
    import resource

    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        memory = memory_mb * 1024 * 1024
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        if hasattr(resource, "RLIMIT_CORE"):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _terminate_process(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _bounded(data: bytes) -> bytes:
    if len(data) <= MAX_OUTPUT_BYTES:
        return data
    marker = b"\n[runner truncated output at configured limit]\n"
    return data[: MAX_OUTPUT_BYTES - len(marker)] + marker


def run_suite(
    *,
    suite_envelope: dict,
    authority_public_key: bytes,
    authority_key_id: str,
    expected_suite_id: str,
    expected_suite_version: str,
    output_dir: Path,
    timeout_seconds: int = 60,
    memory_mb: int = 512,
    cpu_seconds: int = 60,
    evidence_lifetime_hours: int = 24,
) -> dict:
    """Run every required check separately and build evidence only on full pass."""
    if not isinstance(suite_envelope, dict) or not isinstance(suite_envelope.get("payload"), dict):
        raise ValueError("A signed conformance suite envelope is required")
    signed_payload = suite_envelope["payload"]
    binding = signed_payload.get("binding")
    if not isinstance(binding, dict):
        raise ValueError("Signed suite binding is required")
    _validate_binding(binding)
    verified_suite = verify_signed_suite(
        envelope=suite_envelope,
        authority_public_key=authority_public_key,
        expected_authority_key_id=authority_key_id,
        expected_suite_id=expected_suite_id,
        expected_suite_version=expected_suite_version,
        expected_binding=binding,
    )
    commands = _validate_commands(verified_suite["commands"])
    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError("Per-check timeout must be between 1 and 300 seconds")
    if not 64 <= memory_mb <= MAX_MEMORY_MB:
        raise ValueError("Memory limit must be between 64 and 1024 MB")
    if not 1 <= cpu_seconds <= MAX_CPU_SECONDS:
        raise ValueError("CPU limit must be between 1 and 300 seconds")
    if not 1 <= evidence_lifetime_hours <= 24 * 7:
        raise ValueError("Evidence lifetime must be between 1 hour and 7 days")
    if not isinstance(output_dir, Path):
        output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("Output directory must be empty")

    started = datetime.now(timezone.utc)
    results: dict[str, dict] = {}
    artifacts: dict[str, bytes] = {}
    total_bytes = 0
    environment = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    with tempfile.TemporaryDirectory(prefix="aibrain-conformance-") as work_root:
        for check_id in sorted(REQUIRED_CHECKS):
            check_dir = Path(work_root) / check_id
            check_dir.mkdir(mode=0o700)
            stdout = b""
            stderr = b""
            return_code = None
            status = "not_run"
            error = None
            try:
                # File-backed capture plus RLIMIT_FSIZE prevents unbounded
                # in-memory pipe buffering when a child floods stdout/stderr.
                with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                    process = subprocess.Popen(
                        commands[check_id],
                        cwd=check_dir,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        shell=False,
                        close_fds=True,
                        start_new_session=True,
                        preexec_fn=_resource_limiter(memory_mb, cpu_seconds),
                    )
                    try:
                        process.wait(timeout=timeout_seconds)
                        return_code = process.returncode
                        status = "passed" if return_code == 0 else "failed"
                        # A command may exit while leaving descendants running.
                        # Reap the entire process group before the next check.
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    except subprocess.TimeoutExpired:
                        _terminate_process(process)
                        status = "unknown"
                        error = "timeout"
                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout = stdout_file.read(MAX_OUTPUT_BYTES + 1)
                    stderr = stderr_file.read(MAX_OUTPUT_BYTES + 1)
            except (OSError, RuntimeError, ValueError) as exc:
                status = "not_run"
                error = type(exc).__name__

            stdout = _bounded(stdout)
            stderr = _bounded(stderr)
            artifact_name = f"{check_id}.log"
            log_content = (
                b"STDOUT\n" + stdout + b"\nSTDERR\n" + stderr
            )
            if len(log_content) > MAX_OUTPUT_BYTES:
                log_content = _bounded(log_content)
            total_bytes += len(log_content)
            if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                raise ValueError("Runner output exceeded total artifact size limit")
            (output_dir / artifact_name).write_bytes(log_content)
            artifacts[artifact_name] = log_content
            results[check_id] = {
                "status": status,
                "return_code": return_code,
                "error": error,
                "artifact": artifact_name,
            }

    finished = datetime.now(timezone.utc)
    suite_bytes = canonical_json(suite_envelope)
    suite_name = "signed-suite.json"
    (output_dir / suite_name).write_bytes(suite_bytes)
    artifacts[suite_name] = suite_bytes
    report = {
        "schema": "aibrain-conformance-run-report-v1",
        "runner": "aibrain-process-runner-v1",
        "suite_id": verified_suite["suite_id"],
        "suite_version": verified_suite["suite_version"],
        "suite_authority_key_id": verified_suite["authority_key_id"],
        "suite_sha256": verified_suite["suite_sha256"],
        "command_sha256": {
            name: hashlib.sha256(canonical_json(commands[name])).hexdigest()
            for name in sorted(commands)
        },
        "limits": {
            "timeout_seconds": timeout_seconds,
            "memory_mb": memory_mb,
            "cpu_seconds": cpu_seconds,
        },
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "results": results,
    }
    report_bytes = canonical_json(report)
    if len(report_bytes) > MAX_OUTPUT_BYTES:
        raise ValueError("Execution report exceeds output limit")
    report_name = "execution-report.json"
    (output_dir / report_name).write_bytes(report_bytes)
    artifacts[report_name] = report_bytes

    passed = all(item["status"] == "passed" for item in results.values())
    response = {
        "status": "passed" if passed else "incomplete",
        "results": results,
        "report": report_name,
        "manifest": None,
    }
    if not passed:
        return response

    manifest = {
        "schema_version": "aibrain-conformance-evidence-v1",
        **binding,
        "executed_at": started.isoformat(),
        "expires_at": (finished + timedelta(hours=evidence_lifetime_hours)).isoformat(),
        "tests": {
            check_id: {"status": "passed", "artifact": results[check_id]["artifact"]}
            for check_id in sorted(REQUIRED_CHECKS)
        },
        "artifacts": {
            name: hashlib.sha256(content).hexdigest()
            for name, content in sorted(artifacts.items())
        },
    }
    # Reuse the server-side verifier locally before exposing a certifiable
    # manifest. This catches schema drift between runner and AIBrain.
    verify_evidence_manifest(manifest, artifacts, now=finished)
    manifest_bytes = canonical_json(manifest)
    (output_dir / "manifest.json").write_bytes(manifest_bytes)
    response["manifest"] = "manifest.json"
    return response


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--memory-mb", type=int, default=512)
    parser.add_argument("--cpu-seconds", type=int, default=60)
    args = parser.parse_args()
    try:
        public_key_b64 = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64", "")
        authority_key_id = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_KEY_ID", "")
        expected_suite_id = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_EXPECTED_ID", "")
        expected_suite_version = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_EXPECTED_VERSION", "")
        if not all((public_key_b64, authority_key_id, expected_suite_id, expected_suite_version)):
            raise ValueError("Pinned suite authority and approved suite identity/version must be provisioned")
        try:
            public_key = base64.b64decode(public_key_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("Pinned suite-authority public key encoding is invalid") from exc
        result = run_suite(
            suite_envelope=_load_json(args.suite),
            authority_public_key=public_key,
            authority_key_id=authority_key_id,
            expected_suite_id=expected_suite_id,
            expected_suite_version=expected_suite_version,
            output_dir=args.output_dir,
            timeout_seconds=args.timeout_seconds,
            memory_mb=args.memory_mb,
            cpu_seconds=args.cpu_seconds,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Conformance runner failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
