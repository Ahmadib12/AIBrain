# AIBrain Implementation Status

## Latest milestone increment — M11–M14

A first coordinated M11–M14 implementation increment is present on
`dev/tool-authorization-lifecycle`:

- M11: production external-action adapters now have an additional
  composition-time readiness gate bound to provider, adapter/version, account
  scope, verifier, pinned transport, and conformance evidence. Existing
  operator certification and one-time passkey approval remain mandatory.
  No production external action adapter is registered.
- M12: a consent-gated `GET /api/v1/personal/digital-twin` endpoint projects
  explicit owner-approved preferences, goals, and projects; transient context
  and inferred observations are excluded. The repository reads active consent
  and its memory generation in one query.
- M13: trusted provider profiles and policy-aware routing enforce execution
  location, data classification, capabilities, cost tier, and data residency
  when trusted server-side requirements are supplied. No real provider or
  local inference runtime is enabled.
- M14: deterministic bounded plans can be mapped to durable M9 read-only run
  proposals through `POST /api/v1/agent-tasks/{task_id}/plan-runs`. The route
  never authorizes or executes; the owner must use the separate M9 lifecycle.

These are implementation additions, not a claim that production external
actions, real model providers, cross-device synchronization, or autonomous
consequential execution are complete. See
`docs/architecture/milestones-m11-to-m14.md` for scope and verification.

This document distinguishes implemented foundations from external integrations that require additional credentials, hardware, or platform support.

## Implemented

- SQLite migrations and versioned persistence.
- Owner-scoped agent task claiming is atomic across competing workers. Claims
  transition an assigned task to `in_progress`, preserve the worker identity
  in immutable task/control history, and reject already claimed or expired tasks.
- Agent tasks support bounded worker leases, heartbeat renewal, stale-lease
  reconciliation, and owner-scoped requeueing. Reconciliation changes no run
  or tool outcome automatically; uncertain external outcomes remain
  `outcome_unknown` and are never retried.
- Task leases include a unique UUID token and monotonically increasing
  generation. Heartbeats and worker task transitions require the current token;
  expired workers cannot complete or overwrite a newer worker claim. Stale
  takeover is serialized by PostgreSQL row locking and audited.
- Planning rejects common instruction-override and authorization-self-grant
  attempts as control paths, preventing those requests from selecting or
  authorizing capabilities.
- PBKDF2-SHA256 password hashes and bearer sessions.
- User registration, login, logout, account deletion, and protected personal APIs.
- User-owned memory with a versioned consent ledger, database-enforced consent gates,
  authenticated CRUD/export/search, per-request intelligence opt-in, retention,
  revocation, and deletion controls (M6.1–M6.6 implemented and verified; 778 tests
  passing in Codespaces on 2026-11-24).
- Behavioral-learning observations, expiring adaptation proposals, owner decisions, immutable governance events, and user-reported outcome evaluations (M7.1–M7.6 implemented and verified in Codespaces on 2026-11-24: 785 tests passed; compilation and dependency checks passed).
- Provider timeout, fallback, health monitoring, and bounded health-check locking.
- Safe tool contracts and a read-only echo tool.
- Multimodal and streaming event Pydantic contracts.
- Deterministic SSE-style intelligence response delivery.
- A local-provider interface that is disabled until a real runtime is configured.
- An advanced-AGLI processing engine interface that does not claim implementations.

## Partial

- Personal memory retrieval currently uses deterministic lexical ranking; semantic/vector
  retrieval, automatic memory extraction, and cross-device synchronization are not implemented.
- Behavioral learning: evaluation evidence is currently user-reported and descriptive; automatic telemetry, causal attribution, model training, and automatic adaptation application are not implemented.
- AGLI: metadata and provider-independent interfaces exist, but language detection, translation, and speech implementations require engines or credentials.
- Tools: contracts, persistent request/attempt lifecycle, proposal-bound passkey approval, external adapter certification, and a read-only echo implementation exist. No production provider adapter is enabled.
- Agents: M8.1–M8.6 identity, lifecycle, capability governance, task control, same-owner coordination, audit, and recovery are implemented and verified. M9 governed execution is verified in Codespaces on 2026-11-24: 823 full-suite tests passed, compilation passed, and dependency checks were clean. M9 supports digest-bound run proposals, explicit owner authorization, live grant/task/agent revalidation, read-only-only execution through the existing ToolExecutionGateway, immutable run definitions, and append-only run events. Current runtime supports only the registered read-only echo tool; no state-changing or consequential agent action is enabled.
- M10.1–M10.14 integration security foundations are implemented. They include
  owner-scoped pending connections, exact-scope consent, encrypted credential
  storage, trusted verifier lifecycle, immutable run bindings, durable dispatch
  records, asynchronous read-only orchestration, dispatch-time authority checks,
  pinned HTTPS transport, bounded response handling, provider-readiness gates,
  and stale-dispatch recovery. No production provider adapter is registered;
  integrations remain read-only. M10.11–M10.14 were locally verified on
  2026-11-25 with 53 targeted tests and 901 full-suite tests passing, and
  `pip check` clean. See
  `docs/security/integration-security-phases-m10-11-to-m10-14.md`.
- Android and desktop: no application projects are present; only backend contracts can support future clients.
- Multimodal: typed media and event contracts exist, but image/document processing and real-time voice are not implemented.
- Providers: the deterministic mock provider exists; no external provider credentials or local runtime are active.

## External dependencies

The following require user-supplied credentials or unavailable infrastructure:

- Real external AI providers.
- Local model runtimes and downloaded model artifacts.
- Speech recognition and synthesis engines.
- Production database credentials and managed deployments.
- Android or desktop native runtimes.
- Hardware voice features and platform permissions.
- Live calling, VoIP, and third-party telephony integrations.

## Safety boundaries

- User access is enforced by bearer sessions on personal, memory, learning, and tool APIs.
- Memory is scoped to the authenticated user ID; writes and assistant retrieval require
  active consent, while owner review, export, and deletion remain available after revocation.
- Memory is not sent to an intelligence provider unless the authenticated request opts in;
  saved records are framed as untrusted context, not policy or authorization.
- Learning observations do not grant permissions or automatically apply adaptations.
- Agent registration creates draft identities only. Agent existence and metadata do not grant capabilities or authorize execution; registration event history is append-only outside account erasure.
- M9 agent runs must be explicitly owner-authorized and may invoke only registered READ_ONLY contracts through the existing gateway; state-changing and consequential agent actions are rejected.
- M10 integration manifests and adapter registrations are trusted application configuration, not user-supplied runtime plugins. The catalog rejects non-read-only tools and declares required scopes. Owner consent creates only pending grants; the runtime requires active owner connections and exact grants. No provider adapter is registered, and no connection can be activated through a public API.
- Provider and adapter exceptions are sanitized through existing public error mappings.
- Decision traces contain counters and safe categories rather than raw provider or request data.

## Persistence and security remediation

- Account deletion removes memory, observations, adaptations, tool requests, agent identities, agent control records, and agent run/step/event records transactionally after owner tombstoning, revokes sessions, and anonymizes audit records.
- Memory listing, retrieval, update, and export exclude expired records.
- Memory writes require an active owner consent at both repository and database-trigger
  boundaries; revocation blocks retrieval and supports optional physical purge.
- Account deletion removes memory items and memory-consent history, plus integration connection metadata, scope grants, and connection lifecycle events.
- Personal memory, observation, adaptation, and tool payloads have serialized-size,
  nesting, collection, JSON, and credential-like-value limits.
- Tool requests persist their owner, status, deadline, and consumed state.
- Read-only echo execution consumes its confirmation once and rejects replay.
- SQLite uses thread-local connections, an RLock around transactions, foreign-key
  enforcement, busy timeout, and WAL for file-backed databases.
- In-memory SQLite remains available for isolated tests.
- Login attempts have a configurable process-local rate limit.
- Process-local rate limits and in-memory health/session state are not production
  distributed protections.
- PostgreSQL remains opt-in and not selected by AppState. The adapter now
  rejects SQLite `BEGIN IMMEDIATE` composition and agent control/execution paths
  use normal PostgreSQL transactions outside SQLite; row-locking and
  `SKIP LOCKED` patterns remain repository-specific. Dedicated PostgreSQL
  acceptance infrastructure is required before composition is enabled.
- SSE cancellation propagates `CancelledError`; no personal state is added to the
  existing public SSE response contract.
