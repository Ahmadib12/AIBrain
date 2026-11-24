# AIBrain

AIBrain is a foundation for a universal, adaptive, multi-model AI assistant. This repository currently implements the backend and the initial Global Language Intelligence (AGLI) foundation.

## Requirements

- Python 3.11 or newer
- A virtual environment

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

## Run the backend

```bash
uvicorn backend.app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`. Interactive documentation is available at:

- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI: `http://127.0.0.1:8000/openapi.json`

## API endpoints

- `GET /health` — liveness health check
- `GET /api/v1/health` — versioned health check
- `GET /api/v1/agli/languages` — list registered languages
- `GET /api/v1/agli/languages/{code}` — look up a language
- `GET /api/v1/providers` — list registered providers
- `GET /api/v1/providers/status` — provider health monitoring status
- `POST /api/v1/providers/health/{provider_id}` — run a provider health check
- `POST /api/v1/providers/chat` — route a test chat request

## Run tests

```bash
pytest
```

## Implemented in this milestone

- FastAPI application entry point
- Environment-based configuration
- Structured JSON logging
- Standard application error responses
- Versioned API routing
- Health endpoints
- AGLI language and dialect metadata schemas
- In-memory language registry
- Language lookup and validation
- Explicit capability status tracking
- pytest application and registry tests
- Provider-independent interfaces and schemas
- In-memory provider registry
- Priority-based model router
- Determinable mock AI provider
- Bounded fallback and retry handling
- Provider health monitoring
- Environment configuration for providers, priorities, timeout, retries, fallback, and mock behavior

## Provider configuration

Provider behavior can be configured through environment variables:

- `AIBRAIN_MOCK_PROVIDER_ENABLED` — enable or disable the mock provider
- `AIBRAIN_PROVIDER_PRIORITIES` — comma-separated provider priority values, for example `mock:100`
- `AIBRAIN_PROVIDER_TIMEOUT_SECONDS` — provider request timeout
- `AIBRAIN_PROVIDER_HEALTH_CHECK_TIMEOUT_SECONDS` — provider health-check timeout
- `AIBRAIN_PROVIDER_MAX_ATTEMPTS` — bounded attempts per provider
- `AIBRAIN_FALLBACK_ENABLED` — enable or disable fallback routing
- `AIBRAIN_MOCK_PROVIDER_SIMULATE_FAILURE` — make the mock provider fail predictably
- `AIBRAIN_DATABASE_URL` — SQLite database URL, default `sqlite:///:memory:`
- `AIBRAIN_TOOL_EXECUTION_RECOVERY_INTERVAL_SECONDS` — recovery worker polling interval, default `60`
- `AIBRAIN_TOOL_EXECUTION_STALE_AFTER_SECONDS` — age after which a claimed execution is marked `outcome_unknown`, default `300`

The recovery worker starts with the FastAPI application and stops during shutdown. It only marks stale attempts as `outcome_unknown`; it never retries or re-dispatches a tool. An uncertain external outcome must be reconciled explicitly.
- `AIBRAIN_SESSION_TTL_SECONDS` — bearer-session lifetime in seconds
- `AIBRAIN_LOGIN_RATE_LIMIT_ATTEMPTS` — process-local login failure limit
- `AIBRAIN_LOGIN_RATE_LIMIT_WINDOW_SECONDS` — process-local login limit window

The mock provider is intentionally deterministic and does not call external services.

## Capability status model

AGLI capability profiles use four states:

- `registered`: metadata exists in the registry
- `implemented`: code implements the capability
- `available`: an implemented capability is usable in the current runtime
- `verified`: availability has been evaluated with passing tests or benchmarks

Registering a language does not claim that translation, speech recognition, or speech synthesis is implemented.

## Current limitations

- No real external AI provider integration
- No real provider API credentials or paid-service calls
- No language-detection model
- No speech recognition or synthesis
- No live-call or mobile functionality
- No production deployment configuration
- No Android or desktop application project
- No real local-model runtime
- No real tool implementations with consequential side effects
- No complete distributed synchronization system

## Implemented foundations beyond the original milestones

- SQLite migrations and versioned persistence
- PBKDF2 password storage and bearer sessions
- Tenant-isolated personal-memory repositories and APIs
- Explicit behavioral-learning observation and adaptation approval
- Safe tool discovery and a read-only echo tool gateway
- Local-provider and advanced-AGLI interfaces
- Typed multimodal and stream-event contracts
- SSE-style intelligence response endpoint
- Bounded health-check timeout and per-provider health-check locking

### External tool execution safety contract

The design requirements for external state-changing tool adapters, provider
idempotency, uncertain outcomes, authorization binding, reconciliation, and
adapter conformance are documented in [External Tool Execution Safety Contract](docs/external-tool-execution-safety-contract.md).

Provider-neutral typed declarations are available in
`backend/app/tools/contracts.py`: adapter capability metadata, normalized
external outcomes, and a canonical action digest bound to the user, tool
arguments, tool contract fingerprint, adapter version, and provider scope.
These are contracts only; they do not dispatch external actions or enable
state-changing execution. Unit tests are in
`tests/test_external_tool_execution_contracts.py`.

A provider-neutral adapter protocol and immutable canonical action envelope
are defined in `backend/app/tools/external.py`. A deterministic in-memory
fake provider is available in `backend/app/tools/fake_provider.py` for
conformance testing only. It can simulate a response timeout after acceptance,
deduplicate identical keys when provider-enforced idempotency is declared,
reject same-key/different-action submissions, and resolve outcomes through
read-only lookup. In non-idempotent mode, repeated submissions deliberately
create duplicate effects. It is not registered with or connected to the
application gateway. Tests are in
`tests/test_fake_external_tool_provider.py`.

Migrations 10–12 add immutable dispatch bindings, append-only dispatch
audit events, adapter certifications, and revocations. Migration 13 adds
immutable conformance evidence packages and artifact bytes. Certification now
requires a verified evidence-package ID and explicit operator approval; raw
caller-supplied Boolean results and report hashes are no longer accepted.
The verifier canonicalizes the manifest, checks exact provider/adapter/version/
scope/tool/contract/capability binding, validates every required test result,
checks timestamps and bounded artifact sizes, and hashes the actual artifact
bytes. Certification use re-verifies the stored package and its binding. `ExternalToolDispatcher` now provides
a guarded, provider-neutral execution boundary: it claims only passkey-authorized
state-change requests, freezes the exact adapter/provider/capability snapshot,
revalidates authorization and binding immediately before dispatch, and records
one dispatch start plus a normalized outcome. Transport exceptions become
`outcome_unknown`; automatic retries are never attempted. Provider lookup is
read-only and separately audited. These components are not wired into the
application gateway or API routes, and no real provider is registered. The
existing state-changing execution path remains disabled. Tests are in
`tests/test_tool_execution_bindings.py` and
`tests/test_external_tool_dispatcher.py`.


### Provider-neutral bounded conformance process runner

The provider-neutral runner implementation is `scripts/conformance_runner.py`. It requires an Ed25519 authority-signed suite envelope containing the exact provider/tool binding, suite ID/version, and command map for all ten required conformance checks. The runner verifies the signature against a deployment-pinned public key before executing any command. Each check runs as a separate subprocess with a clean environment, stdin closed, no shell, a fresh temporary working directory, bounded wall time, POSIX CPU/address-space/file-size/open-file/core-dump limits, and bounded captured output. The test subprocesses do not inherit the runner API token or signing-key environment variables.

The runner records each check as `passed`, `failed`, `unknown` (timeout), or `not_run` (process could not start). It always emits an execution report. It creates a certifiable evidence manifest only when every required check exits successfully; manifest and artifact digests are generated from the runner's execution output, not accepted as caller-supplied pass claims.

Example invocation:

```bash
export AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64="<pinned-public-key-base64>"
export AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_KEY_ID="suite-authority-2026-01"
python -m scripts.conformance_runner \\
  --suite signed-conformance-suite.json \\
  --output-dir ./conformance-output
```

The signed suite payload schema is `aibrain-conformance-suite-v1`; its signature covers the suite identity, version, exact provider/tool binding, and every argv command. The suite-authority public key and key ID must be pinned by the runner deployment through `AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64` and `AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_KEY_ID`, not supplied by the suite file or command line. The private suite-authority key is kept offline and separate from the runner attestation key. The runner records the signed suite as an evidence artifact and binds its digest, per-command digests, and execution limits into the execution report. A signature proves that the authority approved the exact commands; it does not prove that human-authored test logic correctly exercises a provider guarantee. Review and version-control suite source before signing.

**Isolation limitation:** this is a bounded POSIX subprocess supervisor, not yet a hostile-code sandbox. It does not create a network namespace, enforce provider-domain egress allowlists, or isolate the child from the runner account's kernel. Deploy only inside a separately hardened ephemeral VM/container with a dedicated unprivileged account, read-only source, and externally enforced network policy and container/cgroup PID limits. Keep signing keys and ingestion credentials in a separate submission step after test execution; never mount them into the test environment. The existing evidence verifier, trusted-runner attestation, and independent operator approval remain mandatory. Production dispatch remains disabled.

Runner tests: `pytest -q tests/test_conformance_runner.py`.


The execute-then-attest orchestration entry point is
`scripts/run_and_attest_conformance.py`. It runs the conformance suite first;
only a complete passing result permits evidence loading and submission. The
runner ingestion token and Ed25519 private key are read from the parent
environment only after test subprocesses have exited and the manifest has been
generated and verified. Provision these credentials only to the trusted
orchestration process, never to the test subprocess environment.

Example:

```bash
python -m scripts.run_and_attest_conformance \
  --binding runner-binding.json \
  --commands conformance-commands.json \
  --output-dir ./conformance-output \
  --api-base-url https://aibrain.example \
  --key-id registered-runner-key \
  --runner-id isolated-runner-01
```

Required orchestration environment variables:
`AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_PUBLIC_KEY_B64`,
`AIBRAIN_CONFORMANCE_SUITE_AUTHORITY_KEY_ID`,
`AIBRAIN_TRUSTED_RUNNER_INGEST_TOKEN`, and
`AIBRAIN_RUNNER_PRIVATE_KEY_B64`. The signing key must correspond to a
registered, non-revoked public key scoped to the exact provider, adapter,
version, provider account, tool, and contract fingerprint in the binding.

This orchestration does not create the required OS-level sandbox. Use an
ephemeral hardened VM/container with externally enforced egress policy,
read-only source, an unprivileged identity, and cgroup/container resource
limits. A signed, pinned suite definition and reviewed provider test source remain part of
the trust boundary. Keep the suite-authority private key separate from the
runner signing key. The workflow does not enable production dispatch.

### Inspecting and reconciling uncertain tool executions

Authenticated users can inspect their own persisted tool request and execution-attempt state:

`GET /api/v1/tools/requests/{request_id}`

If recovery has marked an attempt `outcome_unknown`, the owner may record a manually verified outcome:

`POST /api/v1/tools/requests/{request_id}/reconcile`

Successful reconciliation request:

```json
{
  "outcome": "succeeded",
  "note": "Checked the external service and confirmed completion.",
  "result": {
    "verified": true
  }
}
```

Failed reconciliation request:

```json
{
  "outcome": "failed",
  "note": "Checked the external service; the operation was not applied.",
  "error_code": "external_not_applied"
}
```

The `note` is required and limited to 1,000 characters. A successful outcome requires a result object and cannot include an error code. A failed outcome cannot include a result. Only the authenticated owner can inspect or reconcile the request. Reconciliation is an owner-recorded attestation, not independent verification by AIBrain: operators must check the external system before submitting it. Reconciliation updates the persisted request and attempt atomically; it does not retry or dispatch the tool. Duplicate or non-uncertain reconciliation attempts are rejected.

Concurrency and transaction-integrity coverage for this lifecycle is in
`tests/test_tool_execution_concurrency.py`. It exercises competing reconciliation
requests, concurrent recovery workers using separate SQLite database connections,
a recovery/reconciliation race, and rollback when an attempt update fails. Run it
with:

```bash
pytest -q tests/test_tool_execution_concurrency.py
```

The tests verify that request and attempt state remain aligned and that only one
reconciliation can transition an uncertain attempt. Recovery remains conservative:
it records uncertainty and never retries an external operation.

Application lifespan integration tests are in `tests/test_app_lifespan.py`.
They verify that the recovery worker starts before the application serves,
stops before shared application state is reset, and that state cleanup still
runs if worker startup or shutdown raises an exception. Run them with:

```bash
pytest -q tests/test_app_lifespan.py
```

Additional passkey execution-claim invariants are covered in
`tests/test_webauthn_repository.py`: claim rollback on attempt persistence failure,
rejection of deleted accounts, and rejection of altered challenge-to-proposal
bindings. These tests do not enable state-changing execution.


Conformance evidence manifests use schema
`aibrain-conformance-evidence-v1`. The verifier checks byte integrity and
manifest consistency, but SHA-256 is not producer authentication: packages
currently have `unattested` provenance until a trusted sandbox runner
attestation or provider signature is implemented. A successful local
verification must not be represented as proof that a provider actually ran the
tests. This milestone does not enable production adapters or external
state-changing execution.


### Trusted evidence provenance and attestation authority

Migration 14 adds Ed25519 trusted-runner public-key registration, key rotation
by registering a new key ID, append-only key revocation, signed canonical
evidence attestations, and one-time nonce replay protection. Attestations bind
the exact evidence package, manifest and artifact hashes, runner identity,
provider/adapter/version/scope, sandbox label, and validity window. Certification
now requires a valid, non-revoked runner attestation and cannot outlive it.
Active certification lookup rechecks the signature and key status.

AIBrain never stores runner private keys. The runner ingestion API uses
`AIBRAIN_TRUSTED_RUNNER_INGEST_TOKEN`. Key registration, key revocation,
certification approval, and certification revocation use the dedicated
`AIBRAIN_SECURITY_OPERATOR_TOKEN`. Provider administration retains the
separate `AIBRAIN_PROVIDER_OPERATOR_TOKEN`. All three credentials must be at
least 32 characters, have distinct values (configuration rejects reuse), and
be provisioned independently through the deployment secret manager.

Runner API:
- `POST /api/v1/tools/runner/evidence` — submit the manifest and base64 artifacts.
- `POST /api/v1/tools/runner/evidence/{package_id}/attestation-payload` — obtain the exact canonical statement for the runner to sign locally.
- `POST /api/v1/tools/runner/evidence/{package_id}/attest` — submit the Ed25519 signature and consume the one-time nonce.

Operator API:
- `POST /api/v1/tools/operator/trusted-runner-keys` — register a public key.
- `POST /api/v1/tools/operator/trusted-runner-keys/{key_id}/revoke` — revoke a key.
- `POST /api/v1/tools/operator/evidence/{package_id}/certify` — approve certification separately.
- `POST /api/v1/tools/operator/certifications/{certification_id}/revoke` — revoke certification.

Runner endpoints require `X-AIBrain-Runner-Token`; security operator endpoints
require `X-AIBrain-Security-Operator-Token`. The existing
`X-AIBrain-Operator-Token` remains limited to provider administration. Neither
the runner token nor provider operator token can register signing keys, revoke
them, or approve adapter certifications. Private signing keys remain outside
AIBrain. The security operator credential is currently a shared bearer secret;
production deployments still need individual operator identities, stronger
audit attribution, secret rotation, and a controlled key-registration
ceremony.

A signature proves possession of a registered key, not that a sandbox was
genuine or uncompromised. Hardware-backed remote attestation and deployment of
an independently trusted runner remain future operational work. Production
external execution remains disabled.

Trusted runner keys are scoped to one exact provider ID, adapter ID and
version, provider account scope, tool ID, and tool-contract fingerprint.
Register a separate key for every distinct trust scope. A key for one provider,
adapter, tool, account, or contract revision cannot attest another binding.

The external runner client is `scripts/submit_conformance_evidence.py`. It
accepts a completed manifest and its artifact directory, uploads the evidence,
requests AIBrain's canonical signing payload, signs it locally with
`AIBRAIN_RUNNER_PRIVATE_KEY_B64`, and submits the attestation. The script does
not run provider tests or create the evidence manifest: an independently
controlled runner job must run the provider-specific conformance suite first.
The raw Ed25519 private key must be held only by the isolated runner.

GitHub Actions CI is defined in `.github/workflows/ci.yml` and runs the full
test suite on Python 3.11 and 3.14 for pushes to `main` and `dev/**` branches
and for pull requests. This generic CI workflow does not itself establish
provider-specific conformance or trusted-runner status.


Request-body limits remain 1 MiB by default for ordinary endpoints.
`AIBRAIN_RUNNER_EVIDENCE_MAX_REQUEST_BODY_BYTES` defaults to 15 MiB and applies
only to the `/api/v1/tools/runner/evidence` route family; conformance artifacts
are independently capped at 2 MiB each and 10 MiB total.
