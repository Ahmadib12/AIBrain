# Integration security phases M10.11–M10.14

These phases extend the integration security foundation documented in
[integration-security-phases-m10-7-to-m10-10.md](integration-security-phases-m10-7-to-m10-10.md).
They do not certify a provider integration or enable a production provider.

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
caller-supplied Host/connection/proxy/framing headers, control characters,
header injection, and oversized request headers are rejected.

## M10.12 — Request and response bounds

The transport has configurable, hard-capped socket inactivity timeouts, request
header count/value/aggregate limits, response body limits, response header
count/aggregate size limits, and returns only a small allowlist of response
metadata headers. It validates response framing, rejects ambiguous duplicate
Content-Length/Transfer-Encoding headers, checks declared body lengths, and reads
at most the configured body limit plus one byte to detect overflow. Redirect
responses are rejected rather than followed.

The timeout is a socket connect/read inactivity timeout, not a hard wall-clock
deadline for a complete response. Adapters must execute the transport within
the integration runtime's enclosing operation deadline. The Python HTTP parser
also applies its standard per-line and header-count limits before the stricter
post-parse aggregate limit is checked. This is a bounded parser surface, not
a claim of a custom streaming header parser.

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

## Verification boundary

Run the targeted transport/readiness tests, the existing integration security
tests, then the complete suite and dependency check. A green deterministic test
suite verifies these local controls only; it does not replace provider-specific
OAuth/OIDC verification, live TLS interoperability tests, production secret
rotation, or deployment-level egress controls.
