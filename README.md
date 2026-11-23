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
