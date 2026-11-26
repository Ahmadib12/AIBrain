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
not provide remote device attestation.


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
crashed workers do not permanently strand notifications. SMTP delivery is
optional and starts only when explicitly configured; successful delivery is
recorded by the supervised worker.

Remote device attestation and a distributed rate-limit service also remain
unimplemented.


### SMTP delivery for recovery notifications

The recovery notification outbox has an optional supervised SMTP delivery path. Delivery is disabled unless both `AIBRAIN_SECURITY_NOTIFICATION_SMTP_HOST` and `AIBRAIN_SECURITY_NOTIFICATION_SENDER` are explicitly configured. When enabled, the worker uses SMTP STARTTLS with the platform's default certificate-verifying SSL context; it never falls back to plaintext. SMTP credentials are optional for relays that do not require authentication, but username and password must be configured together. Passwords use secret-valued settings and must be supplied through the deployment secret manager, not source control.

The worker claims bounded batches with leases sized for sequential delivery at the configured SMTP timeout, sends plain-text messages, and marks successful sends delivered. Failures are returned to pending with exponential backoff capped at one hour. After eight failed attempts, a notification moves to the terminal `failed` state with a generic failure code and timestamp; it is no longer automatically retried. `delivery_counts()` exposes aggregate pending, processing, delivered, and failed counts without returning recipient data. A crashed process leaves a processing lease that the outbox reclaims after expiry. This is at-least-once delivery: a process crash after the SMTP server accepts a message but before the database records delivery can result in a duplicate email. No credentials, recovery codes, private keys, or full audit payloads are included in messages or logs. Without SMTP configuration, the worker does not start and notifications remain durably pending.

Configuration:
- `AIBRAIN_SECURITY_NOTIFICATION_SMTP_HOST`
- `AIBRAIN_SECURITY_NOTIFICATION_SMTP_PORT` (default `587`)
- `AIBRAIN_SECURITY_NOTIFICATION_SMTP_USERNAME` (optional)
- `AIBRAIN_SECURITY_NOTIFICATION_SMTP_PASSWORD` (optional secret; paired with username)
- `AIBRAIN_SECURITY_NOTIFICATION_SENDER`
- `AIBRAIN_SECURITY_NOTIFICATION_SMTP_TIMEOUT_SECONDS` (default `10`)
- `AIBRAIN_SECURITY_NOTIFICATION_WORKER_INTERVAL_SECONDS` (default `30`)
- `AIBRAIN_SECURITY_NOTIFICATION_BATCH_SIZE` (default `10`)

The transport and worker are covered by mocked SMTP and lifecycle tests. A real SMTP provider has not been configured or integration-tested in this repository, so production delivery is not yet verified.


### Terminal failure handling (Migration 44)

Migration 44 adds a terminal `failed` status, `failed_at`, and a non-sensitive `failure_code`. The worker permits at most eight delivery attempts. The final failed attempt is recorded rather than endlessly retried, and failed notifications are excluded from pending counts and future claims. This is an operational dead-letter state, not a guaranteed operator alert or automatic redrive mechanism; a secure owner/operator review and controlled requeue workflow remain future work.


### Controlled dead-letter operations and shared recovery-abuse monitoring (Migration 45)

Security operators authenticated through the existing security-operator email allowlist can inspect dead-letter metadata at
`GET /api/v1/security-notifications/dead-letter`, review immutable operator events, and redrive an individual failed notification with a required reason through
`POST /api/v1/security-notifications/dead-letter/{notification_id}/redrive`.
Redrive is atomic, resets the delivery attempt counter, clears terminal failure fields, increments a redrive counter, and appends an immutable operator audit event. The list response deliberately omits recipient addresses and message payloads. Redrive is explicit and never automatic.

`GET /api/v1/security-notifications/metrics` exposes aggregate queue counts, oldest active queue age, and aggregate recovery-abuse counters. It does not expose account identifiers, recipient addresses, or raw abuse scopes.

Recovery challenge rate limiting now uses an atomic fixed-window counter in the application database rather than a process-local memory limiter. The persisted scope is a SHA-256 digest of the normalized account email, so changing device IDs does not bypass the account-level limit; raw identifiers are not stored. Processes sharing the same database coordinate their counters. This is cross-process/shared-database protection, not a claim of multi-region protection: deployments must use a genuinely shared, highly available database and separately test their network-edge controls. The current SQLite implementation does not provide a distributed multi-region rate-limiting service.

The SMTP integration smoke test is opt-in and must be pointed at a dedicated test mailbox or SMTP sandbox using `AIBRAIN_SMTP_INTEGRATION=1` and `AIBRAIN_SECURITY_NOTIFICATION_SMTP_TEST_RECIPIENT`. It is intentionally skipped in ordinary test runs. No real provider credentials or recipient are committed.
