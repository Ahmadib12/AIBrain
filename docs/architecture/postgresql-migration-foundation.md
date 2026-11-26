# PostgreSQL migration foundation

The first PostgreSQL migration runner is now isolated under
`backend/app/persistence/postgres/`. It uses psycopg 3, a stable PostgreSQL
session advisory lock to serialize migration runners, and one transaction per
migration. Migration versions are ordered and checked for unknown applied
versions; a failed migration is rolled back and is not recorded as applied.

Migration 1 establishes the PostgreSQL identity/session baseline. Migration 2
ports memory, observations, adaptations, audit events, the current tool-request
shape, WebAuthn credentials/challenges/recovery codes, and tool authorizations.
It also adds a shared active-account insert guard for user-owned records.
These are the first foundational slices, not full parity with SQLite migration
45, and do not make PostgreSQL selectable by the application.

Install the optional driver with:

```bash
python -m pip install -e '.[postgres,test]'
```

The migration runner is an isolated foundation. Before application use, the
remaining migrations must port all tables, indexes, constraints, triggers,
append-only rules, account-erasure behavior, and concurrency invariants. The
runner also needs a real PostgreSQL integration test in CI before the
PostgreSQL backend can advance toward AppState integration.
