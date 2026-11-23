"""Canonical verification for external-adapter conformance evidence.

SHA-256 verifies artifact integrity against supplied bytes; it does not prove
who produced those bytes. Production provenance requires a trusted runner or
provider signature and is intentionally not claimed by this module.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Mapping

REQUIRED_CHECKS = frozenset({
    "stable_idempotency_key",
    "payload_mismatch_rejected",
    "concurrent_deduplication",
    "timeout_after_acceptance_lookup",
    "timeout_before_acceptance_proven",
    "ambiguous_lookup_stays_unknown",
    "lookup_never_dispatches",
    "sanitized_provider_output",
    "binding_change_rejected",
    "no_provider_fallback",
})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 10 * 1024 * 1024
_MAX_ARTIFACTS = 64


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Evidence must be finite, JSON-serializable data") from exc


def verify_evidence_manifest(
    manifest: dict,
    artifacts: Mapping[str, bytes],
    *,
    now: datetime | None = None,
) -> dict:
    """Verify canonical manifest structure, binding, freshness and artifact bytes."""
    if not isinstance(manifest, dict) or not isinstance(artifacts, Mapping):
        raise ValueError("Manifest and artifacts are required")
    required = {
        "schema_version", "provider_id", "adapter_id", "adapter_version",
        "provider_scope", "tool_id", "tool_contract_fingerprint",
        "capabilities", "test_suite_version", "sandbox_environment",
        "executed_at", "expires_at", "tests", "artifacts",
    }
    if set(manifest) != required:
        raise ValueError("Evidence manifest fields are incomplete or unknown")
    if manifest["schema_version"] != "aibrain-conformance-evidence-v1":
        raise ValueError("Unsupported evidence manifest schema")
    for field in (
        "provider_id", "adapter_id", "adapter_version", "provider_scope",
        "tool_id", "test_suite_version", "sandbox_environment",
    ):
        value = manifest[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ValueError(f"Invalid evidence binding: {field}")
    fingerprint = manifest["tool_contract_fingerprint"]
    if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
        raise ValueError("Invalid tool contract fingerprint")
    capability_fields = {
        "idempotency_mode", "key_scope", "idempotency_retention_seconds",
        "rejects_payload_mismatch", "concurrent_deduplication",
        "supports_outcome_lookup",
    }
    capabilities = manifest["capabilities"]
    if not isinstance(capabilities, dict) or set(capabilities) != capability_fields:
        raise ValueError("A complete capability snapshot is required")
    if capabilities["idempotency_mode"] not in ("none", "provider_enforced"):
        raise ValueError("Capability idempotency mode is invalid")
    for field in ("rejects_payload_mismatch", "concurrent_deduplication", "supports_outcome_lookup"):
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
            raise ValueError("Provider-enforced idempotency snapshot is incomplete")
    elif (
        capabilities["key_scope"] is not None
        or capabilities["idempotency_retention_seconds"] is not None
        or capabilities["rejects_payload_mismatch"] is True
        or capabilities["concurrent_deduplication"] is True
    ):
        raise ValueError("Non-idempotent snapshot cannot claim deduplication")
    if not isinstance(manifest["sandbox_environment"], str):
        raise ValueError("Sandbox environment is required")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Verification clock must be timezone-aware")
    try:
        executed = datetime.fromisoformat(manifest["executed_at"])
        expires = datetime.fromisoformat(manifest["expires_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Evidence timestamps must be ISO timestamps") from exc
    if executed.tzinfo is None or expires.tzinfo is None:
        raise ValueError("Evidence timestamps must include a timezone")
    if executed > current or expires <= current or expires <= executed:
        raise ValueError("Evidence is future-dated, expired, or has invalid lifetime")

    declared = manifest["artifacts"]
    if not isinstance(declared, dict) or not declared or len(declared) > _MAX_ARTIFACTS:
        raise ValueError("Manifest must declare a bounded artifact set")
    if set(declared) != set(artifacts):
        raise ValueError("Supplied artifacts do not exactly match the manifest")
    total = 0
    verified_hashes = {}
    for name, expected in declared.items():
        if not isinstance(name, str) or not name or len(name) > 256 or "/" in name or "\\\\" in name or "\x00" in name:
            raise ValueError("Artifact names must be safe logical identifiers")
        if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
            raise ValueError("Artifact digest must be lowercase SHA-256")
        content = artifacts[name]
        if not isinstance(content, bytes) or not content:
            raise ValueError("Evidence artifacts must be non-empty bytes")
        if len(content) > _MAX_ARTIFACT_BYTES:
            raise ValueError("Evidence artifact exceeds size limit")
        total += len(content)
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise ValueError(f"Evidence artifact hash mismatch: {name}")
        verified_hashes[name] = actual
    if total > _MAX_TOTAL_BYTES:
        raise ValueError("Evidence package exceeds total size limit")

    tests = manifest["tests"]
    if not isinstance(tests, dict) or set(tests) != REQUIRED_CHECKS:
        raise ValueError("Evidence must include the exact required conformance tests")
    for test_id, result in tests.items():
        if (
            not isinstance(result, dict)
            or set(result) != {"status", "artifact"}
            or result["status"] != "passed"
            or not isinstance(result["artifact"], str)
            or result["artifact"] not in verified_hashes
        ):
            raise ValueError(f"Missing, failed, or ungrounded conformance test: {test_id}")

    canonical = canonical_json(manifest)
    return {
        "manifest": json.loads(canonical),
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "artifact_sha256": verified_hashes,
        "verified_at": current.astimezone(timezone.utc).isoformat(),
        "expires_at": expires.astimezone(timezone.utc).isoformat(),
        "conformance_results": {name: True for name in sorted(REQUIRED_CHECKS)},
    }
