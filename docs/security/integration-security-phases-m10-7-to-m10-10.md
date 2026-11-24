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

## M10.11 — Pinned HTTPS transport

`backend.app.tools.integration_transport.PinnedProviderHTTPTransport` is the
first concrete transport boundary. It resolves only through the existing
exact-host egress policy, selects one address from the validated immutable DNS
snapshot, dials that IP directly, and retains the allowlisted DNS hostname for
TLS SNI and certificate hostname validation. The peer IP is checked after
connect. The transport does not use environment proxy settings, does not
follow redirects, and does not retry against a different address.

The default SSL context performs certificate-chain and hostname validation.
No insecure TLS mode is exposed. Only GET and HEAD are accepted; request bodies,
caller-supplied Host/connection/proxy/framing headers, control characters, and
header injection are rejected.

## M10.12 — Request and response bounds

The transport has configurable, hard-capped socket inactivity timeouts, request
header count/value limits, response body limits, response header count/aggregate
size limits, and returns only a small allowlist of response metadata headers.
It reads at most the configured body limit plus one byte to detect overflow.
Redirect responses are rejected rather than followed.

The timeout is a socket connect/read inactivity timeout, not a hard wall-clock
deadline for a complete response. Adapters must execute the transport within
the integration runtime's enclosing operation deadline. The Python HTTP parser
also applies its standard per-line and header-count limits before the stricter
post-parse aggregate limit is checked. This is a bounded parser surface, not a
claim of a custom streaming header parser.

## M10.13 — Transport security conformance

`tests/test_integration_transport.py` covers pinned-IP dialing with original
hostname TLS SNI, peer-IP mismatch, prohibited methods and headers, request
body rejection, allowlist and URL rejection, redirect rejection, and response
header/body bounds. Existing egress tests cover mixed public/private DNS
answers, malformed DNS answers, and DNS failure. These tests use deterministic
fakes; they do not constitute a live provider TLS interoperability test or
provider-specific security certification.

## M10.14 — Production provider readiness gate

Production adapters marked with `production_provider = True` cannot be
registered in `IntegrationAdapterRegistry` without trusted composition-time
`ProviderReadinessEvidence`. The evidence must bind the integration ID,
verifier ID, exact non-empty verified scopes, pinned transport identifier, and
the M10.11–M10.13 conformance suite version, with both provider-verification
and transport-conformance results explicitly true. Request data cannot supply
this evidence.

This is a fail-closed composition gate, not proof that a provider is safe:
trusted application composition must create evidence only after real
provider-specific verifier and conformance implementations have passed review.
No production provider adapter is included or activated by these phases.
State-changing and consequential integration operations remain blocked.
