# Session security audit lifecycle

Migration 40 adds an append-only, owner-scoped history for server-issued sessions.

## Events

The database emits these events in the same transaction as the session state change:

- `session.created` when a session row is inserted;
- `session.revoked` when `revoked_at` changes from null to a timestamp;
- `session.expired` when cleanup deletes a session whose expiry has passed.

The expiry event is emitted by the cleanup/delete path, not at the exact wall-clock instant a session expires. A session that has expired but has not yet been cleaned up will not yet have an expiry event.

## Correlation and privacy

Each session receives a server-generated opaque `audit_ref`. It is immutable and is not an authentication credential. The event stream uses this reference to correlate creation, revocation, and expiry without copying the bearer token or its SHA-256 token hash into audit records.

Events contain only the owner, opaque session reference, optional device ID, authentication method, event type, and timestamp. They do not contain tokens, token hashes, passwords, proof nonces, signatures, IP addresses, or user-agent strings.

Existing sessions are assigned opaque audit references during migration. Historical lifecycle events are not fabricated for sessions that predate migration 40.

## Access and retention

Authenticated owners can read their own history through `GET /api/v1/auth/security-events`. Pagination is bounded to 1–100 records and uses a stable timestamp/event-ID cursor. Cross-owner reads are not permitted.

Event rows are immutable and cannot be individually deleted. They are erased only as part of account erasure. Session cleanup can delete live session rows without deleting their audit history.

## Verification boundary

The migration and tests verify local SQLite trigger atomicity, immutable session correlation, owner scoping, bounded pagination, logout revocation, and cleanup-time expiry events. They do not provide remote log shipping, tamper evidence against a privileged database administrator, anomaly detection, or a production incident-response pipeline.


## Session inventory and selective revocation

Authenticated owners can inspect currently valid sessions through
`GET /api/v1/auth/sessions`. Each entry contains the opaque session reference,
optional device ID, authentication method, creation and expiry timestamps, and
an `is_current` marker derived by comparing the request's bearer-token hash
with the stored session hash. Bearer tokens and token hashes are never returned.
Expired, revoked, and device-invalid sessions are excluded.

An owner can revoke one other active session through
`DELETE /api/v1/auth/sessions/{session_ref}`. The operation is owner-scoped and
uses an immediate database transaction; a successful state change causes the
Migration 40 trigger to append the matching `session.revoked` event atomically.
Unknown, expired, revoked, and cross-owner references all return the same
not-found response. The session making the request cannot be revoked through
this endpoint; it must be ended through `POST /api/v1/auth/logout` so the
caller does not invalidate its own request context mid-operation.

This is an application-level session inventory and revocation control. It does
not yet provide device recovery, cryptographic key rotation, or remote device
attestation.
