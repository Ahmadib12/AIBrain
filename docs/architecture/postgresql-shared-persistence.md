# PostgreSQL shared-persistence rollout

Status: **not production-enabled**. The application continues to select SQLite
only. Redis distributes recovery-abuse counters; it does not make SQLite-backed
account, session, device, notification, or audit state shared between hosts.

## Why a URL switch is unsafe

The current persistence layer is not a thin SQL driver wrapper. Its migration
engine is SQLite-specific: 45 ordered migrations, SQLite trigger syntax, JSON1
functions, sqlite_master, sqlite3.complete_statement, and BEGIN IMMEDIATE.
Repository code also depends on SQLite behavior such as qmark parameters,
sqlite3.Row mappings, lastrowid, SQLite upsert syntax, and write-lock
serialization. Adding a PostgreSQL driver or accepting a postgresql URL would
create a false sense of support and can silently weaken race-sensitive
security operations.

## Schema parity inventory

The baseline inventory of all 45 SQLite migrations, 56 tables, 60 indexes,
and 139 distinct triggers is maintained in
[`postgresql-schema-parity-inventory.md`](postgresql-schema-parity-inventory.md).
It records the security invariants that must be ported and tested. The counts
are a coverage checklist, not a claim that PostgreSQL currently has parity.

## Required implementation gates

1. **Persistence contract** — introduced in
   backend/app/persistence/contracts.py. The existing SQLite database
   structurally implements the connection, transaction, and shutdown contract.
   This is an architectural seam, not a PostgreSQL adapter.
2. **PostgreSQL-native migrations** — partially implemented in the isolated
   ordered migration stream. Versions 1–18 currently cover SQLite migration
   domains 1–27, including dispatch recovery, lookup authorization, execution
   reconciliation, memory consent, learning history, agent lifecycle, capability
   grants, tasks, messages, and bounded agent runs. Repository compatibility and full multi-instance invariant parity
   remain outstanding. Port every remaining table, check, unique/index
   constraint, foreign key, append-only rule, account-active guard, lifecycle
   transition, notification outbox trigger, operator redrive audit, claim-token
   fencing, recovery-abuse windows, and account-erasure behavior.
   Do not translate SQLite trigger SQL mechanically.
3. **Repository compatibility** — still required. Audit every repository for
   SQLite-only SQL/API assumptions. Use explicit dialect-aware implementations
   where portability would obscure correctness. Preserve row shapes and
   domain error behavior.
4. **Concurrency and recovery** — still required. Use PostgreSQL transactions
   and row-level locking (including FOR UPDATE SKIP LOCKED for queue claims
   where appropriate), claim-token fencing, and atomic conditional updates.
   Prove single-use recovery codes/challenges, session revocation, key
   rotation, audit/outbox writes, dead-letter redrive, and worker lease
   recovery under independent processes.
5. **Multi-instance acceptance** — still required. CI must launch PostgreSQL
   and Redis services and run at least two independently constructed
   application instances against the same services. Include kill/restart
   tests around notification delivery and database/Redis outage tests.

## Backend-selection safety rule

Do not add PostgreSQL as an accepted DATABASE_URL scheme until all five
gates pass. Unsupported schemes must continue to fail closed at startup.
SQLite remains the default for local development and tests.

## Acceptance checklist

- [ ] PostgreSQL schema reaches parity with SQLite schema version 45.
- [ ] Migration upgrades are transactional, serialized, and restart-safe.
- [ ] All repositories pass backend conformance tests.
- [ ] Security invariants pass against PostgreSQL, not only SQLite.
- [ ] Two application instances share sessions, devices, recovery state,
      notification outbox, audit records, and operator redrive state.
- [ ] Concurrent notification workers claim each row once; stale claim tokens
      cannot acknowledge or release a newer claim.
- [ ] Crash recovery is tested after claim, during send, and before delivery
      acknowledgement.
- [ ] PostgreSQL + Redis CI acceptance suite is green.
- [ ] Deployment documentation and backup/restore procedures are reviewed.
