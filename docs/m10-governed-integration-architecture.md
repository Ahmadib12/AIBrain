# M10 — Governed Tool Integration and Real-World Agent Operations

**Status:** M10 foundation committed on `dev/tool-authorization-lifecycle`. The integration catalog and its read-only/risk/scope invariants are implemented. M10 is not complete: no real external provider adapter is enabled, and owner integration grants, credential lifecycle, execution wiring, and provider-specific conformance remain verification gates.

## Objective

Extend M9's bounded, owner-authorized execution model to real services without creating a second authorization path or allowing agents to inherit broad account access.

M10 introduces a provider-neutral integration boundary. Each connector is application-registered, versioned, namespaced, least-privilege, and described by immutable tool contracts. Owner approval of an agent run remains separate from authorization to access a particular external account or resource.

## Non-negotiable security invariants

1. **No caller-supplied adapters.** HTTP requests may select a registered integration/tool but cannot submit Python modules, adapter instances, callback names, URLs to execute, or arbitrary provider configuration.
2. **Owner-scoped connections.** A connection and its grants belong to one account. Agent identity, task assignment, and capability grants do not imply access to a connected account.
3. **Least privilege.** Each tool declares exact scopes. A connector must reject requests whose required scopes are absent, expired, revoked, or owned by another account.
4. **Risk is immutable at execution time.** Tool contract fingerprint, integration ID/version, adapter ID/version, declared scopes, and risk are revalidated before dispatch.
5. **M10 agent execution begins read-only.** Search, list, inspect, and fetch operations may be considered only after provider-specific review. Writes, sends, purchases, deletes, permission changes, and other consequential operations remain blocked from agent runs.
6. **Existing authorization remains authoritative.** M9's explicit run authorization does not replace connection consent, tool confirmation, WebAuthn/passkey approval, or provider-side authorization.
7. **Credential isolation.** Access/refresh tokens must never be stored in ordinary tool arguments, run plans, event details, logs, model context, or API responses. A future secret store must encrypt credentials with an independently managed key and support rotation/revocation.
8. **No ambient network access.** Adapters must use fixed provider endpoints, strict TLS, bounded timeouts and response sizes, redirect controls, DNS/IP protections, and explicit outbound policy. User-supplied URLs must not become a generic fetch primitive.
9. **Unknown outcomes are not retries.** For state-changing operations, use the existing execution-attempt, idempotency, reconciliation, attestation, and certification machinery. Never blindly retry a timed-out side effect.
10. **Auditable and recoverable.** Record owner, connector, scope identifiers, contract fingerprint, approval reference, attempt ID, outcome class, and timestamps without storing secrets or unnecessary personal payloads.
11. **Revocation is effective before the next action.** A revoked grant blocks subsequent steps; it cannot retroactively undo a provider action already accepted.
12. **Account erasure.** Connection metadata, grants, credential references, audit records, and pending operations must follow the account-erasure policy; external provider revocation may require a separate best-effort workflow.

## M10 workstreams

### M10.1 — Integration catalog and contracts

- Application-owned registry of versioned integration manifests.
- Namespaced tool IDs and stable contract fingerprints.
- Explicit required-scope declarations per tool.
- Reject state-changing and consequential tools from this catalog's agent-facing read-only surface.
- Public catalog metadata excludes credential and adapter internals.

**Implemented in this foundation commit:** `IntegrationManifest`, `IntegrationTool`, and `IntegrationRegistry` in `backend/app/tools/integrations.py`, with focused tests for namespace, risk, scope, duplicate registration, and defensive-copy behavior.

### M10.2 — Owner connection and consent lifecycle

- Create a connection only after explicit owner consent and provider OAuth/credential verification.
- Store only encrypted secret references in a dedicated secret abstraction; never return secret material.
- Scope grants to integration, connection, provider account, and exact scopes.
- Support list, revoke, rotate, expire, and disconnect operations.
- Enforce owner isolation at repository and database boundaries.

### M10.3 — Read-only adapter runtime

- Trusted application registration of provider adapters.
- Adapter contract for bounded reads, typed results, timeout and cancellation.
- Validate input/output schemas and redact sensitive fields.
- Enforce outbound host policy and SSRF protections.
- No arbitrary URL, shell, filesystem, or code execution tool.

### M10.4 — M9 agent-run integration

- Bind each run step to integration ID, connection ID, adapter version, tool contract fingerprint, and required scopes.
- Revalidate the owner connection, owner consent, agent grant, task ceiling, contract, and adapter immediately before each step.
- Keep run-level owner authorization digest-bound and separate from connector consent.
- Persist provider request/response references and redacted outcomes.

### M10.5 — State-changing operation gate

- Keep writes disabled for agent runs until explicit confirmation semantics are designed per action.
- Reuse proposal-bound WebAuthn approval, execution attempts, idempotency guarantees, trusted adapter certification, and outcome reconciliation.
- Do not treat OAuth consent as approval for each future consequential action.
- Fail closed if provider idempotency or outcome lookup guarantees are unknown.

### M10.6 — Operational hardening and conformance

- Provider-specific sandbox conformance suites and signed evidence.
- Credential rotation and revocation tests.
- Cross-owner isolation, scope downgrade, expiry, and race-condition tests.
- Timeout, cancellation, unknown outcome, duplicate dispatch, and audit redaction tests.
- Rate limits, quotas, bounded payloads, provider health, and operational telemetry.

## Initial connector policy

Candidate integrations, in order of risk:

| Integration | Initial allowed operations | Deferred operations |
|---|---|---|
| Web search | Search and retrieve bounded public results through a vetted provider | Arbitrary URL fetch, authenticated browsing, form submission |
| Notes | List and read owner-authorized notes | Create, edit, delete, share |
| Calendar | Read events and availability | Create, update, cancel, invite |
| Files | List metadata and read explicitly selected files | Write, delete, execute, broad recursive access |
| Email | Search and read explicitly authorized messages | Draft, send, forward, delete, attachment execution |
| Device | Read status only after native permission design | Camera, microphone, location, calls, messaging, control |

These are target boundaries, not claims that any integration is currently implemented.

## Current implementation boundary

- M9 remains the only active agent-run execution path and currently supports registered read-only `echo`.
- M10's integration catalog is a validated registry foundation; it does not yet load provider adapters or make network requests.
- No OAuth flow, secret vault, browser/search/calendar/notes/files/email/filesystem/device provider, or credential is enabled by this commit.
- Existing external state-changing dispatcher remains separately governed by signed conformance evidence and proposal-bound passkey authorization; M10 must not bypass it.
- Production deployment, managed secret storage, outbound egress controls, and provider accounts are prerequisites for real integrations.

## Verification gate

Run after pulling the M10 foundation commit:

```bash
git pull --ff-only
python -m compileall -q backend tests scripts
pytest -q tests/test_integration_registry.py
pytest -q tests/test_agent_execution.py
pytest -q tests/test_external_tool_dispatcher.py
pytest -q
python -m pip check
```

Do not mark M10 complete until owner connection/consent, credential isolation, adapter execution, M9 run binding, revocation, provider conformance, account erasure, and the full verification suite are implemented and pass. Keep all work on `dev/tool-authorization-lifecycle`; do not merge to `main` without explicit approval.
