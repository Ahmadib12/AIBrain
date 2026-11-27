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
4. Port dialect-specific queries repository-by-repository, starting with identity/session and device proof, then WebAuthn/tool execution, agents/integrations, memory/learning, and notifications.
5. Add cross-backend repository conformance and concurrency acceptance before enabling application composition.

## Current gate status

- [x] PostgreSQL migration stream 1–36 passes real PostgreSQL CI.
- [x] SQLite implements the structural persistence protocol.
- [x] First-pass repository compatibility inventory recorded.
- [x] SQL-aware qmark conversion and hybrid-row primitives (isolated; tested in `tests/test_postgres_compat.py`).
- [x] Initial opt-in PostgreSQL connection/row/ordinary-transaction adapter.
- [ ] PostgreSQL-safe replacements for SQLite `immediate=True` transaction assumptions.
- [~] Protocol decoupling now covers tool requests, device proof, integration vault, identity, memory, learning, tool runtime, agent control/execution, agent registry, integration connections, device registry, notification outbox and operations, recovery-abuse monitor, WebAuthn repository constructor, and session/device security-event services. A complete repository-wide constructor/type audit and SQL compatibility review are still required.
- [ ] Repository SQL portability.
- [ ] PostgreSQL repository conformance suite.
- [ ] Cross-instance security/concurrency acceptance.
- [ ] PostgreSQL application composition and deployment acceptance.
