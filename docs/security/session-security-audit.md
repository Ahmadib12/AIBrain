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
not provide remote device attestation.\n

## Device key rotation

Migration 41 adds a dedicated rotation challenge store and the
`device.key_rotated` immutable audit event. Rotation is available only for an
active, already-keyed device owned by the authenticated account.

The owner submits the replacement Ed25519 public key to
`POST /api/v1/devices/{device_id}/key-rotation/challenge`. The server creates a
five-minute, one-use challenge bound to the device, owner, current key
fingerprint, replacement key fingerprint, and nonce. This prevents a challenge
issued for an earlier key version from being reused after another rotation. The device must sign the exact returned message with
both its existing private key and the replacement private key. The signatures
are submitted to
`POST /api/v1/devices/{device_id}/key-rotation/verify`.

The server verifies both signatures inside an immediate transaction, consumes
the challenge, replaces the public key and fingerprint, revokes every active
session bound to that device, and appends a key-rotation audit event containing
only the previous and new public-key fingerprints. The database rejects key
replacement unless a matching consumed rotation challenge is awaiting its
single application. The event contains no private key, signature, nonce, or
bearer token.

This flow protects a device when both old-key and replacement-key possession
are available. It is not a lost-device recovery mechanism: when the old private
key is unavailable, rotation must not be bypassed by an ordinary account
session. Recovery requires a separate high-assurance process.


## Lost-device recovery

Migration 42 extends the device key rotation challenge with an optional
recovery-code reference and updates the database key-change guard. Ordinary
rotation still requires both old and replacement private-key signatures.
Recovery is a separate unauthenticated flow and never accepts an ordinary
account session as its authorization factor.

Owners first provision ten high-entropy recovery codes through
POST /api/v1/auth/passkeys/recovery-codes after password reauthentication.
Only SHA-256 digests are stored. Reissuing the set invalidates every unused
code in the same transaction. The status endpoint returns only the remaining
count; plaintext is returned only at issuance.

To recover a lost device, the replacement installation submits the account
email, one unused recovery code, the target device ID, and its new Ed25519
public key to POST /api/v1/devices/{device_id}/recovery/challenge. The server
checks that the device is active and belongs to that account, validates the
unused code, and creates a five-minute challenge bound to the previous key
fingerprint and replacement key. The replacement installation signs the exact
challenge message with its new private key and submits it to
POST /api/v1/devices/{device_id}/recovery/verify.

The verification transaction rechecks the active account and device, key
version, challenge expiry and replay state, recovery-code state, nonce, and
replacement-key signature. It consumes the recovery code and challenge,
updates the device key, revokes all sessions bound to that device, marks the
challenge applied, and appends the device key-rotation audit event atomically.
A database trigger independently requires the referenced recovery code to be
consumed before accepting a recovery-authorized key replacement. A recovery
code cannot be reused across challenges; only one concurrent verification can
consume it. A successful recovery does not create a session: the replacement
device must perform the normal device login proof with its new key.

This recovery flow requires two independent factors: possession of a
single-use recovery code and possession of the replacement private key. It
does not require the lost key, and it does not treat a normal account session
as sufficient.

Migration 43 adds a durable notification outbox. The same transaction that
writes a recovery key-rotation audit event enqueues one
`device.recovery.completed` notification for the account email. The outbox
payload contains only the device ID and event timestamp; it excludes recovery
codes, signatures, nonces, and key fingerprints. Claims use an immediate
transaction, bounded batches, attempt counts, and expiring processing leases so
crashed workers do not permanently strand notifications. Delivery is not yet
enabled: a configured email transport and supervised delivery worker are still
required before the system can claim that an owner was actually notified.

Remote device attestation and a distributed rate-limit service also remain
unimplemented.
