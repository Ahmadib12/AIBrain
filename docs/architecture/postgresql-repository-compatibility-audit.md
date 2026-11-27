# PostgreSQL repository compatibility audit

Status: **audit baseline established; no PostgreSQL repository adapter is enabled**.

Branch: `dev/tool-authorization-lifecycle`  
Audit baseline: commit `7a56b2d`  
Scope: application persistence repositories plus the device-proof and integration-vault persistence services.

## Executive finding

The PostgreSQL migration stream is now accepted by real PostgreSQL CI through version 36, but the application repositories are still written against the SQLite connection surface. The existing `DatabaseProtocol` is only a structural lifecycle/transaction seam; it does not normalize SQL dialects, cursor behavior, row objects, or transaction isolation.

The current application must therefore remain SQLite-only. Do not inject a PostgreSQL database into `AppState` yet.

## First-pass compatibility inventory

The audit inspected all Python modules under `backend/app/persistence/` (excluding the isolated PostgreSQL migration package), plus `backend/app/devices/proof.py` and `backend/app/tools/integration_vault.py`.

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

1. Add SQL-aware parameter and hybrid-row compatibility primitives with isolated unit tests.
2. Add a PostgreSQL connection/transaction adapter implementing `DatabaseProtocol`; keep it opt-in and unused by `AppState`.
3. Convert repository constructor annotations to the protocol and prove the adapter's low-level conformance.
4. Port dialect-specific queries repository-by-repository, starting with identity/session and device proof, then WebAuthn/tool execution, agents/integrations, memory/learning, and notifications.
5. Add cross-backend repository conformance and concurrency acceptance before enabling application composition.

## Current gate status

- [x] PostgreSQL migration stream 1–36 passes real PostgreSQL CI.
- [x] SQLite implements the structural persistence protocol.
- [x] First-pass repository compatibility inventory recorded.
- [ ] PostgreSQL connection/row/transaction adapter.
- [ ] Repository SQL portability.
- [ ] PostgreSQL repository conformance suite.
- [ ] Cross-instance security/concurrency acceptance.
- [ ] PostgreSQL application composition and deployment acceptance.
