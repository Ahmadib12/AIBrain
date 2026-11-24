# Execution History, Audit Integrity, and Retention

Status: Implemented baseline; operational policy and external tamper-evidence remain future work
Scope: External tool dispatch, stale execution recovery, provider outcome lookup, and account erasure
Applies to: SQLite persistence migrations 11, 16, 17, 18, 19, and 20

## 1. Purpose

AIBrain keeps separate records for external dispatch, recovery decisions, and authorization to query a provider about an unknown outcome. These records answer different questions and must not be collapsed into one mutable status field:

- **Dispatch audit:** Did AIBrain cross the provider boundary, and what outcome did the adapter report?
- **Recovery audit:** Did recovery prove that the provider boundary had not yet been crossed?
- **Lookup authorization:** Which trusted certification and runner identity authorized a read-only provider lookup?
- **Execution state:** What is the current state of the request and execution attempt?
- **Manual reconciliation:** What outcome did the user record after independently resolving an uncertain operation?

The four audit ledgers are separate immutable records while an account is active. Request and attempt rows remain the operational state, not substitutes for the ledgers.

## 2. Source records and meaning

### 2.1 Execution request, attempt, and binding

The request row holds the user-owned request, its current lifecycle state, and any final result. The execution-attempt row tracks the claimed/terminal state. The execution-binding row freezes the idempotency key, action digest, canonical payload, adapter identity, provider scope, contract fingerprint, and capability snapshot.

For an external action, the final dispatch gate checks the frozen binding and current authorization/trust conditions in an immediate database transaction. The unique `dispatch_started` event is written before the adapter call. Once that event exists, recovery must not conclude that the provider was never called.

The action digest correlates records to one exact authorized action. It is not a replacement for the payload, and it does not prove that a provider performed the action.

### 2.2 Dispatch audit ledger

Table: `tool_dispatch_audit_events`

Allowed event types:

| Event | Meaning |
|---|---|
| `dispatch_started` | Final authorization gate committed; the provider boundary may now be crossed |
| `dispatch_succeeded` | Adapter returned a definitive success |
| `dispatch_failed` | Adapter returned a definitive failure |
| `dispatch_unknown` | The adapter outcome could not be determined |
| `outcome_lookup` | An authorized read-only provider lookup returned a typed outcome |

Each event is bound to a user, request, action digest, JSON details, and timestamp. Outcome details store an error code and/or evidence reference; the full success result remains in the request's `result_json`, not duplicated into the audit ledger.

A single dispatch may have at most one `dispatch_started` and one terminal dispatch-outcome event. An unknown result is not a retry instruction.

### 2.3 Recovery ledger

Table: `tool_dispatch_recovery_events`

The only current event type is `dispatch_not_started`. Recovery writes it when a stale external execution has a binding but no committed `dispatch_started` event. In the same transaction, the attempt and request are moved to failed with `recovery_dispatch_not_started`.

If a `dispatch_started` event exists, recovery cannot prove the provider did nothing. It moves the request and attempt to `outcome_unknown` instead. A generic execution with no external binding is also conservatively marked unknown.

The table enforces one recovery event per request.

### 2.4 Lookup-authorization ledger

Table: `tool_dispatch_lookup_authorizations`

A lookup authorization records the certification ID and action digest, with details identifying the evidence package, trusted runner key, provider, adapter/version, provider scope, tool, and contract fingerprint.

This row records **permission to make a provider lookup attempt**, not the provider's answer and not a new dispatch. After the provider returns a valid typed outcome, AIBrain writes an `outcome_lookup` dispatch-audit event that references the authorization row's ID.

If the provider lookup raises or returns an invalid response, the authorization row remains as evidence that lookup was authorized; no `outcome_lookup` record is written.

### 2.5 Manual reconciliation

Manual reconciliation is a user decision made after independently determining the uncertain external outcome. It does not call the provider and never retries the action.

Reconciliation is persisted in the dedicated `tool_execution_reconciliation_events` ledger. The request result and request/attempt states are updated in the same immediate transaction. The note and final outcome are not stored only in mutable request JSON. Migration 20 backfills valid legacy `audit_json.execution_reconciliation` values into this ledger and removes the migrated JSON field.

## 3. Lifecycle and ordering

The normal external-dispatch lifecycle is:

1. A passkey-authorized request is claimed and bound to an immutable action envelope.
2. A final transaction rechecks the passkey, request/attempt state, frozen binding, active adapter certification, signed evidence, and trusted runner-key state.
3. That transaction inserts `dispatch_started` and commits.
4. The provider adapter is called **outside** the SQLite transaction.
5. A definitive or unknown outcome is persisted in a separate immediate transaction, together with the request and attempt state update.

Stale recovery is serialized with the final dispatch gate using SQLite's immediate write transaction. If recovery commits first without a start marker, it records `dispatch_not_started` and fails the request. If dispatch-start commits first, recovery sees the marker and reports an unknown outcome instead of assuming no side effect.

Provider outcome lookup follows a separate sequence:

1. The request and attempt must both be `outcome_unknown`.
2. The current adapter must match the persisted binding and support outcome lookup.
3. The certification and complete trusted evidence chain are checked.
4. An immediate transaction rechecks the unknown execution, certification, evidence attestation, runner-key revocation state, and matching `dispatch_started` digest, then inserts the lookup-authorization row.
5. The transaction commits.
6. The adapter's read-only `lookup()` runs outside the transaction.
7. A valid typed provider response is recorded as `outcome_lookup`, correlated to the authorization ID.

The immediate transaction gives revocation and lookup authorization a clear linearization point: if revocation commits first, authorization fails; if lookup authorization commits first, a later revocation does not retroactively cancel the already-authorized in-flight read-only lookup. No database transaction is held open during provider network I/O.

A positive lookup is evidence for a separate reconciliation decision. It does not silently change the request's terminal state.

## 4. Unified repository read model

`ToolRequestRepository.get_execution_history(user_id, request_id)` is an owner-scoped read model over the four source ledgers. It returns a chronological list with:

- `id`, `record_type`, and `event_type`;
- reconciliation outcome, note, and error code for a reconciliation event;
- `action_digest`;
- parsed `details`;
- `created_at`;
- `certification_id` for lookup-authorization records.

The record types remain explicit: `dispatch_audit`, `dispatch_recovery`, `lookup_authorization`, and `execution_reconciliation`. The method does not mutate or rewrite source records. It returns history only for a request owned by the supplied user and raises not-found for another owner.

Rows are ordered by timestamp, then record type and ID as deterministic tie-breakers. Timestamps are application-generated UTC ISO strings; equal timestamps do not establish causal order. Where transaction races matter, the database transaction/commit boundary—not lexical ordering of timestamps or UUIDs—defines which authorization or revocation won.

This is an internal repository method. There is not yet a user-facing or operator-facing HTTP history endpoint, pagination contract, export format, or retention-management API.

## 5. Integrity and deletion behavior

While the account is active:

- dispatch, recovery, lookup-authorization, and reconciliation rows reject updates through SQLite triggers;
- direct deletion of those rows is rejected;
- deleting the parent tool request cannot bypass the row-level delete guard through foreign-key cascading;
- the repositories write lifecycle events and associated state transitions atomically.

Account erasure is the intentional exception. `IdentityRepository.delete_user()` starts an immediate transaction, tombstones the account by setting `deleted_at`, and then deletes its dependent requests and related records. The ledger delete triggers permit the cascade only after the account has been tombstoned. The erasure and dependent deletions occur in the same transaction.

These are **database-level application safeguards, not a WORM archive or protection against a fully privileged database/file operator**. An operator able to replace the database file, disable/drop triggers, alter schema, or modify SQLite pages can bypass them. The event rows are not individually signed or hash-chained. The signed conformance evidence chain protects adapter certification evidence; it does not cryptographically seal every execution-history row.

## 6. Privacy and data minimization

The execution ledger is designed to preserve accountability without copying the full action payload into every event:

- action digests correlate records without embedding the action payload;
- dispatch-start details identify the execution attempt and adapter/provider scope;
- dispatch outcome details contain bounded error/evidence references;
- the full successful result is stored on the request record;
- lookup-authorization details preserve the trust identifiers needed to explain why lookup was allowed;
- recovery details identify the adapter/provider context and the reason the provider boundary was not crossed.

Provider evidence references and result payloads remain potentially sensitive. They must not be copied into general application logs, analytics, or traces without classification, redaction, and a purpose-specific policy.

Account erasure removes the user's request-scoped execution history. This repository behavior does not erase data held by external providers or copies in infrastructure backups. Backup expiry, legal holds, provider-side deletion, and proof of completed erasure require separate operational policies.

## 7. Retention and operational investigation

There is currently no time-based cleanup job for these four execution ledgers. While an account remains active, their rows are retained; deletion is tied to account erasure. Do not introduce a generic TTL cleanup that deletes individual rows without an approved retention policy and an integrity-preserving archive/export design.

For a specific request, an investigation should correlate:

1. the request and execution-attempt state;
2. the immutable execution binding and action digest;
3. the dispatch/recovery/lookup records returned by `get_execution_history()`;
4. the current certification and evidence/attestation references where still retained;
5. the immutable reconciliation event and its note/outcome;
6. provider-side evidence through a separately authorized provider interface.

An `outcome_unknown` state must remain uncertain until evidence supports reconciliation. Do not dispatch again merely because a response was lost or a lookup found no record. Do not reinterpret `dispatch_not_started` as provider failure; it means the provider boundary was not crossed by that execution attempt.

## 8. Known gaps and follow-up requirements

1. **Immutable reconciliation history:** implemented in migration 20 and included in the unified history model. Legacy `audit_json.execution_reconciliation` values are backfilled and removed from the mutable request JSON during migration.
2. **Access surface:** design an authenticated, owner-scoped API and operator-only investigation surface with redaction, authorization, pagination, and export limits.
3. **External tamper evidence:** evaluate signed checkpoints or an external append-only audit sink for production deployments where database-operator tampering is in scope.
4. **Backup and provider erasure:** define backup retention, legal-hold behavior, provider-side deletion requests, and verifiable erasure outcomes.
5. **Retention policy:** approve retention by data class and jurisdiction before adding automatic expiration or archival.
6. **Operational controls:** define alerting for stale unknown outcomes, repeated lookup attempts, revoked trust, and failures to persist outcome events.

Until these gaps are implemented, this document describes the current repository guarantees and explicit limitations; it is not a claim of production-grade tamper-proof audit infrastructure.
