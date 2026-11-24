# M6 Closeout — User-Owned Memory Core

**Implementation status:** M6.1–M6.6 implementation is committed on
`dev/tool-authorization-lifecycle`. Local verification is pending. Do not mark
M6 closed until the focused tests, full test suite, compilation, and dependency
check pass in the Codespaces environment.

## Milestones delivered

### M6.1 — Memory architecture and data model
- Versioned SQLite migration 21 adds a consent ledger and binds memory rows to
  the consent under which they were created.
- Memory remains account-owned and uses the existing owner-scoped repository.
- Existing pre-M6 memory records have a null consent binding. They remain visible
  to their authenticated owner for review, export, and deletion, but are not
  available to assistant retrieval or editing under the new consent model and
  are never silently adopted by a later consent grant.

### M6.2 — Explicit consent and access control
- Memory consent is opt-in and recorded with a policy version, grant timestamp,
  retention policy, and optional revocation timestamp.
- Saving and retrieval require an active consent belonging to the authenticated
  account.
- Database triggers independently reject memory writes without a matching
  active consent and active owner account.
- Revoked consent cannot be reactivated. A new grant creates a new consent
  identity and does not make earlier records available to assistant retrieval.
- Revocation blocks subsequent assistant retrieval, while the owner can still
  list, inspect, export, and delete their own stored records.
- Intelligence requests use `use_memory=false` by default. Setting it to true
  requires an authenticated user and active memory consent.

### M6.3 — Memory creation and organization
- Owner can create, inspect, list, edit, export, and delete records.
- Supported categories: preference, goal, context, and project.
- Owners can edit category, key, value, and confidence.
- Payload size, depth, collection size, JSON types, and credential-like values
  are bounded by the existing personal-data validator.
- Saving is an explicit API operation. M6 does not automatically extract or
  store arbitrary chat content.

### M6.4 — Retrieval and context integration
- Search uses deterministic lexical token overlap and returns a bounded
  relevance score; it is not semantic/vector search.
- Search is limited to the authenticated owner's current-consent records.
- Context assembly returns at most five records and a maximum of 16 KiB of
  provider context.
- Saved records are supplied to the provider as a system-context data block
  explicitly labelled untrusted. They are not policy, instructions, consent,
  or tool authorization.
- Memory is not inserted into the request context unless the current request
  explicitly opts in with `use_memory=true`.

### M6.5 — Retention, deletion, and forgetting
- Default retention is 365 days; owners may select 1–3650 days or null for no
  automatic expiry on newly created records.
- Explicit expiry dates cannot extend beyond the active consent's retention
  ceiling.
- Shortening retention also shortens eligible existing expiry dates; the
  implementation never lengthens an existing expiry when a policy is relaxed.
- Expired records are purged lazily during access and by a background worker
  whose default interval is 3600 seconds.
- Revocation immediately blocks subsequent assistant retrieval. Owner listing,
  inspection, export, and deletion remain available after revocation.
- Optional `purge_existing=true` erases every memory record owned by the user,
  including records created under earlier revoked consents and legacy records.
- Per-record deletion and clear-all remain available after consent revocation.
- Account deletion removes memory records and consent history in the existing
  account-erasure transaction.

### M6.6 — Security, evaluation, and closeout
- Regression coverage added for explicit consent, database write enforcement,
  user isolation, revocation, re-grant isolation, record edits, retention
  ceilings, search/context isolation, account erasure, per-request opt-in,
  provider context framing, and retention-worker lifecycle.
- Compilation, focused tests, full suite, and dependency validation are the
  required local exit checks below.

## API surface

Authenticated personal-memory endpoints:

- `GET /api/v1/personal/memory/consent`
- `POST /api/v1/personal/memory/consent`
- `PATCH /api/v1/personal/memory/consent/retention`
- `DELETE /api/v1/personal/memory/consent?purge_existing=false`
- `POST /api/v1/personal/memory`
- `GET /api/v1/personal/memory`
- `GET /api/v1/personal/memory/{memory_id}`
- `PATCH /api/v1/personal/memory/{memory_id}`
- `DELETE /api/v1/personal/memory/{memory_id}`
- `DELETE /api/v1/personal/memory`
- `POST /api/v1/personal/memory/search`
- `POST /api/v1/personal/memory/context`
- `POST /api/v1/personal/memory/export`

The intelligence `/process` and `/process/stream` request bodies accept
`use_memory`. The default is false. Memory use requires a valid bearer session
and active consent; it is not silently enabled for anonymous users.

## Operational and privacy limitations

- This is a SQLite-backed engineering foundation, not a production certification.
  SQLite files are not encrypted at rest by this change. Production deployment
  still requires a documented encryption/key-management, backup, restore,
  access-monitoring, and disaster-recovery design.
- Search is lexical and deterministic. There is no vector index, embedding
  provider, learned ranking, or autonomous memory extraction.
- Revocation prevents subsequent retrievals. A provider request that already
  received a context snapshot cannot be made to “unsee” it; in-flight requests
  may complete with the snapshot assembled while consent was active.
- Existing legacy memory rows are intentionally excluded because they have no
  consent binding. Owners may clear all records; a later grant never adopts them.
- Behavioral-learning observations and adaptation proposals remain separate
  APIs and are not automatically added to the memory context.
- No mobile/desktop memory management interface is included in this backend
  milestone.

## Verification required

Run from the repository root in the active virtual environment:

```bash
git pull --ff-only

python -m compileall -q backend tests scripts

pytest -q tests/test_memory_core.py \
  tests/test_memory_retention.py \
  tests/test_milestones_foundation.py \
  tests/test_intelligence_api.py \
  tests/test_intelligence_core.py \
  tests/test_app_lifespan.py

pytest -q
python -m pip check
```

Record actual results after running these commands locally. The existing
Starlette/httpx TestClient deprecation warning is known and non-blocking; it
should be addressed separately as a dependency-compatibility task.

## Exit criteria

M6 may be marked complete only after all focused tests, the full suite,
compilation, and dependency checks pass in Codespaces. Preserve the Phase 1
authorization boundary and the M5 planning rule: memory context never grants
permission to execute an action. Do not merge this development branch to
`main` without explicit approval.
