# PostgreSQL repository compatibility audit

Status: **audit baseline established; no PostgreSQL repository adapter is enabled**.

Branch: `dev/tool-authorization-lifecycle`  
Audit baseline: commit `7a56b2d`  
Scope: application persistence repositories plus the device-proof and integration-vault persistence services.

## Executive finding

The PostgreSQL migration stream is now accepted by real PostgreSQL CI through version 36, but the application repositories are still written against the SQLite connection surface. The existing `DatabaseProtocol` is only a structural lifecycle/transaction seam; it does not normalize SQL dialects, cursor behavior, row objects, or transaction isolation.

The current application must therefore remain SQLite-only. Do not inject a PostgreSQL database into `AppState` yet.

## First-pass compatibility inventory

The audit inspected the SQL-bearing persistence modules under `backend/app/persistence/` (excluding the isolated PostgreSQL migration package), plus `backend/app/devices/proof.py` and `backend/app/tools/integration_vault.py`. It also reviewed the database implementation, application composition, persistence protocol, and rollout documentation.

| Surface | First-pass finding | Compatibility implication |
|---|---:|---|
| Repository/service files in scope | 18 | All need a documented compatibility disposition |
| Raw `?` characters in SQL-heavy modules | 1,176 | Must distinguish true bind markers from literals and translate safely; global replacement is unsafe |
| String-key row access expressions | 455 | PostgreSQL rows must preserve both named and positional access where used |
| Concrete `Database` type annotations | 16 | Repositories and services are coupled to the SQLite implementation |
| Explicit `transaction(immediate=True)` calls | 80+ | Must map to a real PostgreSQL serialization/locking strategy, not silently ignore writer-lock assumptions |
| Direct SQLite imports in repository code | 2 files | Review `sqlite3.Row` and exception assumptions |
| `lastrowid` use | 0 in inspected repository/service modules | No last-insert-id adapter requirement found in this pass |

Counts are static first-pass source occurrences, not a proof that every question mark is a bind parameter or every call site has been fully classified. Re-run the inventory as implementation changes.

### Files with the largest SQL/row compatibility surface

- `backend/app/persistence/tool_requests.py` — 306 question-mark characters; 218 string-key row accesses.
- `backend/app/devices/proof.py` — 142 question-mark characters; 53 string-key row accesses.
- `backend/app/persistence/agent_execution.py` — 120 question-mark characters.
- `backend/app/persistence/webauthn.py` — 106 question-mark characters.
- `backend/app/persistence/integration_connections.py` — 97 question-mark characters.
- `backend/app/persistence/agent_control.py` — 76 question-mark characters.

## Security-critical transaction audit (WebAuthn, identity, device proof)

A focused source review of `identity.py`, `devices/proof.py`, and `webauthn.py` confirms that transaction portability is the primary blocker for these repositories; qmark conversion alone is insufficient.

### Identity and sessions

- Registration now translates only the SQLite `users.email` unique-constraint error or PostgreSQL SQLSTATE `23505` with constraint name `users_email_key` into the existing duplicate-email domain error. Other integrity errors propagate unchanged.
- The SQLite and PostgreSQL database adapters now expose a `dialect` marker. Identity session creation uses SQLite `BEGIN IMMEDIATE` as before; on PostgreSQL it locks the active user row with `FOR UPDATE`, then locks an optional active owned device row before inserting the session.
- Account erasure uses the same PostgreSQL user-row lock before tombstoning and deleting dependent state. This establishes a consistent user-before-device lock order for these identity operations.
- Focused fake-connection tests verify emitted PostgreSQL lock statements and order. They are unit tests, not real PostgreSQL concurrency acceptance. Device proof and other account-scoped writers are not yet proven to follow this lock order.
- Account registration performs a read-before-insert email check. Concurrent registrations can both pass the read, so PostgreSQL behavior must rely on the unique email constraint as the final arbiter and translate only the expected unique-violation into the existing domain error.
- Session creation validates that the account (and optional owned active device) is still active before inserting. PostgreSQL implementation must define how account/device deactivation and session creation serialize; merely dropping `immediate=True` creates a time-of-check/time-of-use window.
- Session revocation reads ownership/audit metadata before updating. The update must remain scoped to the same owner and active session, with affected-row checks retained.
- Account deletion is a multi-table tombstone/erasure transaction. It must remain atomic and must not race with session creation, device authentication, or other writes for the same account.

### Device proof

- The device-proof repository now selects its transaction mode by explicit dialect: SQLite retains `immediate=True`; PostgreSQL uses ordinary transactions and explicit account-before-device row locks. Unknown dialects fail closed.
- PostgreSQL lock order is the same owner row before device row used by the identity/session slice. Authenticated proof paths lock the known owner and device; unauthenticated login paths first resolve the trusted owner from the device/challenge record, then acquire owner and device locks in that order.
- Enrollment/session challenge issuance, public-key registration, login proof, activation, active-device proof, key rotation, and recovery rotation now use this locking seam. Conditional challenge/recovery-code updates remain the final single-use guards; activation, last-seen updates, key replacement, and challenge application also check affected-row counts so a failed lifecycle transition rolls back the transaction.
- Key rotation and recovery still revoke device-bound sessions and append the `device.key_rotated` audit event inside the same transaction as key replacement. Recovery verification locks the recovery-code row before consuming it.
- Device registry enrollment now locks the active account row before inserting a pending device; capability reporting and revocation lock account then device before updating. Revocation continues to invalidate device-bound sessions in the same transaction. SQLite retains its previous immediate-transaction behavior.
- The device security-event repository now uses the same explicit dialect transaction selection and account-before-device locks before appending an event. Event pagination remains owner-scoped and read-only.
- Fake-connection tests cover enrollment, capability reporting, revocation, event append, lock order, and transaction selection. They are unit tests only: real PostgreSQL concurrency, trigger parity, and independent-connection acceptance remain outstanding. The API composition is still SQLite-only, and PostgreSQL unique-conflict translation at the device enrollment endpoint has not been completed.

### WebAuthn

- Public-key material is now passed as plain `bytes`, removing the repository's direct `sqlite3.Binary` dependency. SQLite BLOB and PostgreSQL `bytea` binding are compatible at this boundary.
- WebAuthn now has an explicit dialect transaction seam: SQLite retains `transaction(immediate=True)`; PostgreSQL uses an ordinary transaction and locks the active owner row with `FOR UPDATE` before every state-changing credential, challenge, recovery-code, authentication, registration, and tool-authorization operation. This serializes WebAuthn writes per account and shares the account-before-dependent-row lock order used by identity/account erasure.
- Challenge consumption and tool-request approval retain conditional updates plus affected-row checks as final single-use guards. The account lock is a serialization boundary, not a replacement for those guards.
- Authentication and tool authorization read and update credential sign counters while holding the account lock, preventing concurrent WebAuthn operations for one owner from calculating updates from stale counters. This deliberately serializes passkey state changes within an account; a later optimization may narrow this to credential-row locks after proving a global lock order.
- Recovery-code replacement invalidates the old unused set and inserts the replacement set in the same transaction while holding the owner lock. The conditional one-winner semantics for challenge consumption remain in place.
- Added fake-connection lock/transaction tests in `tests/test_postgres_webauthn_locking.py` and opt-in independent-connection acceptance tests in `tests/test_postgres_webauthn_concurrency_integration.py` for sign-counter monotonicity, one-winner challenge consumption, and atomic recovery-code generations. These real PostgreSQL tests require `AIBRAIN_POSTGRES_TEST_URL` and have not yet been executed in the user's Codespace.
- Existing SQLite tests remain in `tests/test_webauthn_repository.py`, `tests/test_webauthn_service.py`, and `tests/test_webauthn_api.py`.

This is an initial PostgreSQL WebAuthn locking implementation, not a completed repository port or acceptance result. Other WebAuthn-adjacent repositories and the application composition remain SQLite-only. The PostgreSQL adapter still correctly rejects `transaction(immediate=True)`.

### Tool-request transition locking — initial slice

The first tool-execution portability slice now adds a repository-owned
transaction boundary for four owner-scoped transitions:
- generic read-only approval;
- generic read-only execution claim plus attempt creation;
- immutable dispatch-binding creation;
- passkey-authorized execution claim plus attempt creation.

SQLite continues to use `BEGIN IMMEDIATE`. PostgreSQL uses an ordinary
transaction and locks the active owner row before the owner-scoped tool-request
row, matching the identity and WebAuthn account-first lock order. Existing
conditional updates and affected-row checks remain in place as the final
single-winner guards. The new fake-connection tests assert lock order and
fail-closed behavior for unsupported dialects.

The same request-scoped lock boundary has now been extended to completion
and failure, external dispatch start, provider outcome recording, provider
outcome-lookup authorization and evidence recording, owner reconciliation, and
pending-request cancellation. These transitions now acquire the owner account
and request locks before applying their existing conditional state changes.
This keeps their request/attempt/audit updates in one transaction while
replacing their dependence on SQLite's global writer reservation.

This is deliberately a first slice, not a completed `tool_requests.py` port.
Stale-attempt recovery, operator-scoped execution history/audit operations,
trusted-runner evidence/certification operations, and global operator writes
still use SQLite immediate transactions or require additional PostgreSQL-
specific query/locking review. The PostgreSQL adapter
must remain out of application composition.

## Required compatibility work

### 1. Connection and row contract

- Implement a PostgreSQL database adapter behind `DatabaseProtocol`, without changing active application backend selection.
- Preserve `connect().execute(...)`, `fetchone()`, `fetchall()`, `rowcount`, named row access, positional row access, and `dict(row)` behavior where used.
- Preserve exception semantics deliberately; translate only known integrity/concurrency failures into domain-level errors.
- Ensure connection ownership is safe across threads and requests. A single shared connection must never be used as the application-wide connection.

### 2. SQL parameter adaptation

- Replace positional qmark markers with psycopg placeholders using a SQL-aware scanner that respects quoted strings, quoted identifiers, comments, and dollar-quoted procedural text.
- Do not use a raw `str.replace("?", "%s")`.
- Audit all query text for SQLite-only syntax/functions separately; placeholder conversion alone is not SQL portability.

### 3. Transaction semantics

- Replace the SQLite `BEGIN IMMEDIATE` writer-lock assumption with explicit PostgreSQL row locks and conditional updates.
- For queue claims, use a PostgreSQL-safe claim transaction (typically `FOR UPDATE SKIP LOCKED`) plus the existing claim-token fencing.
- Prove nested/exceptional transaction behavior and connection cleanup.
- Do not weaken single-use challenges, recovery codes, authorization consumption, audit/outbox atomicity, or stale-worker fencing.

### 4. Dialect-specific SQL inventory

Classify each repository query for:
- SQLite-only `INSERT OR IGNORE` / `INSERT OR REPLACE` forms;
- SQLite JSON1 functions and JSON storage assumptions;
- SQLite-specific conflict/upsert behavior;
- date/time and boolean representation;
- SQLite-specific error codes and constraint handling;
- implicit ordering, rowcount, and cursor assumptions.

Prefer explicit dialect branches for security-critical SQL over a large opaque SQL-rewriting layer.

### 5. Acceptance

- Add a PostgreSQL-backed repository conformance suite covering all repositories, not only migrations.
- Run identical domain scenarios against SQLite and PostgreSQL and compare normalized outcomes.
- Add independent-connection/process tests for races and recovery.
- Keep PostgreSQL out of `AppState` and reject PostgreSQL `DATABASE_URL` until repository, concurrency, and multi-instance gates pass.

## Recommended implementation sequence

1. [x] Add SQL-aware parameter and hybrid-row compatibility primitives with isolated unit tests (`postgres/compat.py`). These primitives are not yet wired into a connection.
2. [x] Add an opt-in PostgreSQL connection adapter implementing `DatabaseProtocol` (`postgres/database.py`). It supports thread-owned connections, psycopg transactions, qmark conversion, and hybrid rows. `transaction(immediate=True)` deliberately fails closed; it is not yet safe for repositories that rely on SQLite writer serialization. The adapter is unused by `AppState`.
3. [~] Convert repository/service constructor annotations to `DatabaseProtocol` in the first security-critical slice (`tool_requests.py`, `devices/proof.py`, and `tools/integration_vault.py`), then extended it to core identity, memory, learning, tool runtime, agent control/execution, agent registry, integration connections, device registry, notification, and session/device security-event services. This follow-up also moved `SecurityNotificationOperations`, the SQLite recovery-abuse monitor, and the WebAuthn repository constructor onto `DatabaseProtocol`. WebAuthn still contains SQLite-specific `sqlite3.Binary` handling; the recovery-abuse monitor and notification redrive still rely on `immediate=True`. The WebAuthn repository now binds public-key material as plain `bytes`, removing its direct `sqlite3.Binary` dependency; this is compatible with SQLite BLOB binding and psycopg `bytea` binding. Its security-critical methods still use `transaction(immediate=True)`, so this does not make WebAuthn PostgreSQL-ready. These are typing/composition seams only: the adapter remains opt-in and no SQL or transaction compatibility is implied.
4. Port dialect-specific queries repository-by-repository. Identity/session and the device-proof/revocation locking slice have initial PostgreSQL branches; remaining device writes, WebAuthn/tool execution, agents/integrations, memory/learning, and notifications are outstanding.
5. Add cross-backend repository conformance and concurrency acceptance before enabling application composition.

## Current gate status

- [x] PostgreSQL migration stream 1–36 passes real PostgreSQL CI.
- [x] SQLite implements the structural persistence protocol.
- [x] First-pass repository compatibility inventory recorded.
- [x] SQL-aware qmark conversion and hybrid-row primitives (isolated; tested in `tests/test_postgres_compat.py`).
- [x] Initial opt-in PostgreSQL connection/row/ordinary-transaction adapter.
- [~] Initial PostgreSQL row-lock replacements for identity/session and device-proof/revocation paths; device enrollment, capability reporting, device revocation, and security-event append now use explicit owner/device locks. Real PostgreSQL device concurrency acceptance tests cover duplicate enrollment and capability-report/revocation races, but remain opt-in via `AIBRAIN_POSTGRES_TEST_URL` and have not been locally executed in the current work session.
- [~] Protocol decoupling now covers tool requests, device proof, integration vault, identity, memory, learning, tool runtime, agent control/execution, agent registry, integration connections, device registry, notification outbox and operations, recovery-abuse monitor, WebAuthn repository constructor, and session/device security-event services. A complete repository-wide constructor/type audit and SQL compatibility review are still required.
- [ ] Repository SQL portability.
- [ ] PostgreSQL repository conformance suite.
- [ ] Cross-instance security/concurrency acceptance.
- [ ] PostgreSQL application composition and deployment acceptance.
