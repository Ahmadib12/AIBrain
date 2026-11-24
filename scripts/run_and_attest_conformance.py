"""Execute the conformance suite, then upload and attest only a complete pass.

The test subprocesses finish before this process reads runner credentials. The
private key is used only by the existing submitter and is never passed to tests.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from scripts.conformance_runner import _load_json, run_suite
from scripts.submit_conformance_evidence import load_evidence, submit_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--api-base-url", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--runner-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--memory-mb", type=int, default=512)
    parser.add_argument("--cpu-seconds", type=int, default=60)
    args = parser.parse_args()

    try:
        # Execute first. Do not read or use any runner credentials until all
        # required checks have completed successfully and the manifest passes
        # the same verifier used by AIBrain.
        authority_public_key_b64 = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64", "")
        authority_key_id = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_KEY_ID", "")
        expected_suite_id = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_EXPECTED_ID", "")
        expected_suite_version = os.environ.get("AIBRAIN_CONFORMANCE_SUITE_EXPECTED_VERSION", "")
        if not all((authority_public_key_b64, authority_key_id, expected_suite_id, expected_suite_version)):
            raise ValueError("Pinned suite authority and approved suite identity/version must be provisioned")
        try:
            authority_public_key = base64.b64decode(authority_public_key_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("Pinned suite-authority public key encoding is invalid") from exc
        result = run_suite(
            suite_envelope=_load_json(args.suite),
            authority_public_key=authority_public_key,
            authority_key_id=authority_key_id,
            expected_suite_id=expected_suite_id,
            expected_suite_version=expected_suite_version,
            output_dir=args.output_dir,
            timeout_seconds=args.timeout_seconds,
            memory_mb=args.memory_mb,
            cpu_seconds=args.cpu_seconds,
        )
        if result["status"] != "passed" or result["manifest"] != "manifest.json":
            print(json.dumps(result, sort_keys=True))
            return 1

        manifest, artifacts = load_evidence(
            args.output_dir / "manifest.json", args.output_dir
        )
        runner_token = os.environ.get("AIBRAIN_TRUSTED_RUNNER_INGEST_TOKEN", "")
        private_key_b64 = os.environ.get("AIBRAIN_RUNNER_PRIVATE_KEY_B64", "")
        if not runner_token or not private_key_b64:
            raise ValueError("Runner ingestion token and signing key must be provisioned")
        attestation = submit_evidence(
            base_url=args.api_base_url,
            runner_token=runner_token,
            private_key_b64=private_key_b64,
            key_id=args.key_id,
            runner_id=args.runner_id,
            manifest=manifest,
            artifacts=artifacts,
        )
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f"Conformance execution/submission failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "status": "attested",
        "execution_report": result["report"],
        "attestation": attestation,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
