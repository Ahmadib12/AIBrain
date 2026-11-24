# Integration security phases M10.7–M10.10

This document records the current implementation boundary. It is not a production security certification and must be updated when provider-specific transports and verifiers are introduced.

## M10.7 — Dispatch-time authority

The dispatch authorization linearization point is the transaction that:
1. acquires the database write lock;
2. revalidates the owner-bound run, immutable binding, manifest version, contract fingerprint, registered adapter, connection state, expiry, and exact required scope grants;
3. persists the dispatch_started ledger transition and audit event; and
4. commits before invoking the adapter.

Connection revocation uses an immediate write transaction against the same database. Therefore, a revocation that commits before the dispatch-start transaction is observed by the authority check and prevents adapter invocation. If dispatch-start commits first, the read operation is already authorized and may be in flight when revocation occurs. Revocation does not claim to cancel a remote request already sent. Results are discarded if authority is no longer active when the runtime returns.

Only READ_ONLY integration contracts are executable. State-changing and consequential integration operations remain blocked.

## M10.8 — Provider transport and egress

ProviderEgressPolicy enforces HTTPS, a lowercase exact-host allowlist, port 443, no userinfo/fragments/IP-literal hosts, and rejects every DNS answer that is not globally routable. resolve_target returns an immutable DNS snapshot (PinnedProviderTarget) for a transport to pin.

A production transport must connect directly to one of the returned IP addresses, preserve the original DNS hostname for TLS SNI and certificate verification, disable redirects and ambient proxy configuration, apply strict connect/read/total timeouts, and bound response headers and body size. It must not perform a second DNS lookup. The helper alone is not an HTTP transport and does not prove socket-level pinning. No production provider adapter is enabled.

## M10.9 — Trusted provider verification

Provider verifiers are registered by trusted application composition; request data cannot register or select a verifier. Activation requires the verifier to return the exact owner-consented scopes, a SHA-256-shaped provider-subject fingerprint, and a finite future expiry. Credential rotation must preserve the previous verified provider subject and exact scope set.

There are no default provider verifiers. Provider-specific signature, issuer/audience, token introspection, and evidence-validation logic must be implemented and independently tested before a real provider can be enabled. A verifier identifier or a syntactically valid fingerprint is not, by itself, proof of provider authenticity.

## M10.10 — Recovery and operations

The integration dispatch recovery worker scans stale dispatch_started records. It atomically marks each abandoned dispatch outcome_unknown, fails the corresponding running step and run, skips later pending steps, and emits immutable audit events. It never calls an adapter and never retries.

Operational deployment still needs provider-specific reconciliation APIs where available, alerting/metrics for unknown outcomes, retention and audit export policies, key rotation/re-encryption operations, and tested multi-process deployment behavior. A timeout or process interruption must not be interpreted as proof that a remote provider did not perform the read.
