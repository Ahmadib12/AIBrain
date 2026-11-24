# External Tool Execution Safety Contract

**Status:** Design contract; typed adapter boundary and test-only fake provider implemented. No production external adapter or dispatch integration is enabled.

This document defines the minimum guarantees required before AIBrain may
dispatch a state-changing action to an external service. It deliberately does
not enable state-changing execution.

## 1. Core safety invariant

AIBrain must never infer that an external action failed merely because it did
not receive a response.

After a dispatch may have reached a provider, a timeout, connection loss,
process crash, malformed response, or ambiguous provider error means
**outcome unknown**. The request remains consumed and must not be dispatched
again unless the provider's documented idempotency contract makes a same-key
retry safe, or an authoritative lookup proves the operation was not applied.

AIBrain does not promise exactly-once execution by itself. Exactly-once effects
cannot be guaranteed across a network boundary without cooperation from the
external provider or target system.

## 2. Required adapter contract

Every external state-changing tool must be implemented by an explicit adapter
registered for that tool. An adapter must expose these conceptual operations:

- **execute(action, idempotency_key):** submit one logical action using the
  supplied stable key; it must not generate a new key for a retry.
- **lookup(idempotency_key):** query the provider for the outcome of that
  logical action. This operation must be read-only and must never submit or
  repeat it.
- A static capability declaration describing the provider's guarantees.

An adapter must identify its provider, adapter version, provider account/tenant
scope, and the tool contract version it implements. These identifiers are
part of the dispatch binding and audit record.

Adapters must return a normalized outcome with one of three meanings:

- **Succeeded:** provider evidence identifies the completed operation.
- **Failed:** provider evidence establishes that the operation was not applied
  or was definitively rejected.
- **Unknown:** the provider may have applied the operation, but AIBrain cannot
  establish the result.

A generic exception must never be silently converted into Failed.

## 3. Idempotency requirements

The execution attempt's persisted request ID is the stable logical-action key.
It must remain unchanged for the entire lifetime of that action.

An adapter must declare one of these modes:

- **None:** the provider does not guarantee deduplication. Once dispatch may
  have occurred, AIBrain must not automatically resubmit.
- **Provider-enforced:** the provider guarantees that repeated submissions
  with the same key and within its documented scope/retention window cannot
  create duplicate effects.

For provider-enforced idempotency, the adapter must document and validate:

1. Key scope (for example, provider account plus endpoint or operation type).
2. Maximum key length and accepted character format.
3. Provider retention period for idempotency records.
4. Whether requests with the same key but different payloads are rejected.
5. Whether the original response or operation reference can be recovered.
6. Whether the guarantee covers concurrent submissions.

AIBrain must bind the idempotency key to a canonical digest of the action. It
must never reuse a key for different arguments, a different user, a different
provider account, or a changed tool/adapter contract. The provider's retention
period must cover the entire period in which AIBrain might retry or recover the
attempt. If any requirement is unknown or not guaranteed, treat the adapter
as non-idempotent.

## 4. Dispatch and outcome rules

| Situation | Required AIBrain behavior |
| --- | --- |
| Validation or authorization fails before dispatch | Do not dispatch; preserve a safe failure state. |
| Provider definitively rejects the request without applying it | Record Failed with a bounded provider error code. |
| Provider confirms completion | Record Succeeded with a sanitized result and provider operation reference. |
| Timeout or connection loss after dispatch may have started | Record/retain outcome_unknown; do not blindly retry. |
| Process crashes after dispatch | Recovery marks outcome_unknown; it does not dispatch. |
| Provider lookup confirms completion | Reconcile to Succeeded with lookup evidence. |
| Provider lookup confirms no operation was applied | Reconcile to Failed; a new attempt requires a new explicit authorization decision. |
| Lookup is unavailable, ambiguous, or inconsistent | Keep outcome_unknown; require further investigation. |

A provider lookup is not a dispatch. A retry is a dispatch and must be treated
as a potentially consequential action.

Automatic retry is prohibited by default. Even for provider-enforced
idempotency, retry behavior must be an explicit, separately reviewed policy
using the exact same key and identical action digest. Provider fallback to a
different provider is prohibited for a dispatched state-changing action.

## 5. Authorization and immutable action binding

Immediately before dispatch, AIBrain must revalidate all of the following:

- Authenticated user and active account.
- Owner-scoped request identity and unexpired authorization.
- Exact tool ID, arguments digest, tool contract fingerprint, and risk level.
- Exact adapter ID and adapter version.
- Exact provider account/tenant scope.
- Passkey authorization bound to the same proposal digest and contract.
- No prior execution attempt or consumed request state that would permit a
  second dispatch.

A successful passkey approval is authorization evidence, not an execution
attempt. The authorization must not be transferable to modified arguments, a
different provider account, a changed adapter, or a different tool version.

Cancellation before dispatch may prevent dispatch. Once dispatch may have
started, cancellation cannot be represented as proof that the external action
was undone. A compensating action, if supported, is a separate action requiring
its own contract and authorization.

## 6. Persistence and audit requirements

Before calling an adapter, AIBrain must durably persist the claimed attempt and
the immutable dispatch binding. The binding should include:

- Request ID and idempotency key.
- Canonical action digest.
- Tool contract fingerprint and version.
- Adapter ID and version.
- Provider account/tenant scope identifier (never credentials).
- Declared idempotency mode and retention deadline.
- Dispatch-start timestamp and bounded correlation metadata.

After the provider responds, persist the normalized outcome, provider operation
reference, timestamps, and sanitized error/result metadata. Never persist
access tokens, secrets, raw authorization assertions, or unfiltered provider
responses.

If persistence of the provider outcome fails, the attempt remains uncertain.
Recovery must use lookup where supported; it must not assume the action failed.

### Current persistence implementation

Migration 10 creates `tool_execution_bindings`, a one-to-one, owner-scoped
snapshot linked to a claimed execution attempt. The repository accepts a
binding only while the request is `executing` and its attempt is `claimed`.
It checks that the idempotency key is the request ID, that the supplied
canonical payload exactly matches the persisted request arguments, that the
tool contract fingerprint matches, and that the action digest recomputes from
the persisted owner/tool/arguments plus adapter identity, provider ID, and
provider scope. The complete supported provider-capability snapshot is
required and validated before storage; partial or unknown capability fields
are rejected. A database trigger prevents updates to a persisted binding.

Migration 11 adds append-only `tool_dispatch_audit_events`. Migration 12 adds immutable adapter certification records and append-only revocations. A certification is scoped to the exact provider, adapter ID/version, provider account scope, and complete capability snapshot. It records a conformance-suite version, SHA-256 test-report digest, evidence references, expiry, and approving operator. Dispatch is refused unless a matching, unexpired, non-revoked certification exists. The
`ExternalToolDispatcher` is a provider-neutral, explicitly invoked boundary
that claims only passkey-authorized state-change requests, persists the binding,
then performs a final transactional check of the active account, request
consumption, passkey authorization, credential revocation state, consumed
challenge, contract fingerprint, canonical arguments, action digest, and exact
adapter/provider/capability snapshot. It records `dispatch_started` before
calling the adapter and permits only one initiation per request.

A normalized provider success or definitive failure is persisted with the
request and attempt transition. Any transport exception or invalid/ambiguous
adapter outcome becomes `outcome_unknown`; the dispatcher never retries.
Read-only provider lookup is available only for unknown attempts, is audited,
and does not silently reconcile the request. Manual reconciliation remains a
separate owner-attestation workflow.

The certification repository exposes an operator/service-layer approval method; it is not a public API. The caller must authenticate and authorize the approving operator before recording a certification. Migrations 12–13 store immutable certifications, revocations, verified manifests, and the exact artifact bytes. Certification issuance accepts only an existing verified evidence-package ID; it no longer accepts caller-supplied Boolean test results or a claimed report digest.

The canonical manifest binds provider ID, adapter ID/version, provider scope, tool ID, tool-contract fingerprint, complete capability snapshot, conformance-suite version, sandbox environment, execution and expiry timestamps, exact required test IDs/statuses, and artifact SHA-256 digests. The verifier rejects unknown or missing fields/tests, failed tests, missing/extra/altered artifacts, unsafe artifact names, oversized packages, invalid/future/expired timestamps, and malformed capability snapshots. Certification approval is a separate operator decision and cannot outlive the evidence package. Active-certification lookup re-hashes the persisted artifact bytes and rechecks the manifest binding before returning a certification.

Important trust boundary: SHA-256 proves that supplied bytes match the manifest's digest; it does not prove who created the manifest, that the named sandbox actually ran, or that a provider's claims are truthful. Evidence packages are explicitly marked `unattested`. A trusted runner attestation or provider signature, with key lifecycle and revocation, remains future work. A certification therefore records operator approval of integrity-checked evidence, not cryptographic proof of provider provenance.

The dispatcher is deliberately not wired into the application gateway or API
routes. No production provider is registered, and state-changing execution
remains disabled. Account deletion continues to cascade through owner-scoped
records. Tests are in `tests/test_tool_execution_bindings.py` and
`tests/test_external_tool_dispatcher.py`.

## 7. Reconciliation rules

Reconciliation should prefer authoritative provider lookup over manual
attestation. The lookup result must be tied to the same provider account,
idempotency key, action digest, and operation reference.

Manual owner/operator attestation remains a last-resort audit mechanism. It
must be clearly labeled as an attestation, record who supplied it and why
provider evidence was unavailable, and must not trigger dispatch.

Conflicting provider evidence must leave the attempt outcome_unknown and raise
an operational alert; it must not be resolved by choosing whichever result is
more convenient.

## 8. Adapter conformance tests

No state-changing adapter may be enabled until its conformance suite proves:

- Stable key reuse across retries and recovery.
- Different action digests cannot share an idempotency key.
- Same-key concurrent dispatches cannot create duplicate provider effects
  when provider-enforced idempotency is claimed.
- Timeout after provider acceptance resolves through lookup without a second
  effect.
- Timeout before acceptance is distinguished only when provider evidence
  proves non-acceptance.
- Ambiguous lookup preserves outcome_unknown.
- Provider lookup never dispatches.
- Adapter/account/contract changes invalidate the dispatch binding.
- Provider error payloads and results are sanitized before persistence.
- No fallback to another provider occurs after a dispatch may have started.

Tests must include deterministic fake-provider scenarios and, before
production enablement, provider sandbox or equivalent integration evidence
for the provider's actual idempotency and lookup guarantees.

## 9. Current AIBrain implementation boundary

The current gateway executes only its local read-only echo implementation.
Passkey-authorized state-changing requests remain non-executable. The existing
recovery worker marks stale claims outcome_unknown and never retries. The
existing reconciliation API records owner attestation; it is not yet a
provider-backed verification workflow.

This design does not change those behaviors. The typed adapter protocol and
immutable canonical action envelope now exist in `backend/app/tools/external.py`.
A deterministic fake provider in `backend/app/tools/fake_provider.py` exercises
provider-enforced idempotency, duplicate effects when idempotency is absent,
pre-acceptance failure, timeout after acceptance, read-only lookup, and
concurrent same-key submissions. Its conformance tests are in
`tests/test_fake_external_tool_provider.py`. The fake is not registered with
the application gateway and cannot perform real-world actions.

Remaining steps are to run the conformance suite against a real provider sandbox, preserve the resulting evidence package, and have an authorized operator approve its digest and scope. A provider-backed reconciliation workflow and independently verifiable evidence are still required before considering one narrowly scoped state-changing adapter behind an explicit feature gate.


## 10. Trusted runner evidence attestation

Migration 14 adds an Ed25519 trusted-runner key registry, append-only key
revocations, and immutable evidence-attestation records. A runner signs a
canonical payload binding the exact evidence package ID, manifest digest,
complete artifact digest map, runner identity, provider/adapter/version,
provider scope, sandbox-environment label, one-time nonce, issue time, and
expiry. AIBrain verifies the signature against a registered public key and
checks key validity, runner identity, evidence freshness, and exact package
binding before consuming the nonce and recording the attestation.

Private signing keys are never stored by AIBrain. Key registration is an
operator-controlled service-layer action; rotation means registering a new
key ID and moving the runner to it. Revocation is append-only and immediately
invalidates certifications that depend on the revoked key. Key records,
revocations, and attestations cannot be updated or deleted. Nonces and
package IDs are unique, preventing attestation replay. Certification requires
a currently valid runner attestation and cannot outlive either the evidence
package or its attestation. Active certification lookup rechecks signature,
key revocation, and attestation expiry. The final transactional
`dispatch_started` gate independently revalidates the exact certification,
evidence digest, artifact bytes, signature, key validity/revocation, scope,
and all relevant expiry bounds before recording dispatch initiation.

The Ed25519 helper can sign payloads for runner-side integration tests, but
production private keys must be generated and protected outside AIBrain (for
example, in a dedicated CI runner secret store or hardware-backed key service).
The runner and operator workflows are exposed through separate API
credential boundaries. `AIBRAIN_TRUSTED_RUNNER_INGEST_TOKEN` authenticates
evidence upload, attestation-payload requests, and signed attestation submission.
`AIBRAIN_SECURITY_OPERATOR_TOKEN` authenticates public-key registration,
key revocation, certification approval, and certification revocation.
`AIBRAIN_PROVIDER_OPERATOR_TOKEN` remains limited to provider administration.
All three tokens must be at least 32 characters, have distinct values (the
settings validator rejects reuse), and are compared in constant time. The
runner and provider credentials cannot perform security operator actions.

Runner API routes:
- `POST /api/v1/tools/runner/evidence`
- `POST /api/v1/tools/runner/evidence/{package_id}/attestation-payload`
- `POST /api/v1/tools/runner/evidence/{package_id}/attest`

Operator API routes:
- `POST /api/v1/tools/operator/trusted-runner-keys`
- `POST /api/v1/tools/operator/trusted-runner-keys/{key_id}/revoke`
- `POST /api/v1/tools/operator/evidence/{package_id}/certify`
- `POST /api/v1/tools/operator/certifications/{certification_id}/revoke`

The attestation-payload endpoint builds the exact canonical statement from the
stored evidence package and registered runner key. The external runner signs
that payload locally and submits only the signature. AIBrain never receives or
stores the private signing key. API responses do not return public or private
key material. Evidence upload has global request-body limits and per-package
artifact size/count limits enforced by the conformance verifier.

The security operator credential is currently a shared bearer secret. The
`approved_by`, `registered_by`, and `revoked_by` fields are operator-provided audit labels,
not independently established human identities. Production operation therefore
still needs individual operator identity/SSO, stronger audit attribution,
secret rotation, and a controlled key-registration ceremony.

Trusted runner keys are scoped to exactly one provider ID, adapter ID and
version, provider account scope, tool ID, and tool-contract fingerprint. A key
registered for one such binding cannot attest another provider, adapter,
version, account, tool, or contract revision; register separate keys for
separate trust scopes. This scope is enforced during payload creation,
attestation ingestion, certification approval, active-certification lookup,
and the final dispatch transaction.

The isolated runner client is `scripts/submit_conformance_evidence.py`. It
uploads an already-generated evidence manifest and its declared artifact
bytes, obtains the canonical attestation payload, signs it locally using the
runner's externally stored Ed25519 private key, and submits the signature.
It deliberately does not generate test reports or claim to have run provider
tests. The independently controlled runner job must execute the provider-
specific conformance suite and construct the manifest before using the client.
The signing key is supplied through `AIBRAIN_RUNNER_PRIVATE_KEY_B64` only in
the runner's secret store and is never transmitted to AIBrain.

The repository GitHub Actions workflow runs compilation and the complete
project test suite on Python 3.11 and 3.14. It is generic project CI, not proof
of a trusted runner environment and not a provider-specific conformance run.
A real provider sandbox, isolated runner deployment, secret-store provisioning,
and successful provider-specific test evidence remain release gates.

A signature proves that the holder of a registered private key signed the
bound statement. It does not independently prove that the sandbox environment
was genuine, that the runner binary was uncompromised, or that tests actually
exercised a live provider. The key-registration authority and runner deployment
remain part of the trust root and require operational controls, independent
runner isolation, key custody, and audit. AIBrain therefore treats this as
authenticated runner provenance, not hardware-backed remote attestation.
Human certification approval remains separate and explicit. No production
provider is registered, and no external state-changing execution is enabled.

GitHub Actions CI is configured in `.github/workflows/ci.yml`. It installs the
project test extra, compiles backend and tests, and runs the complete pytest
suite on Python 3.11 and 3.14 for development/main pushes and pull requests.
The workflow itself must still complete successfully on GitHub before Phase 1
can be marked CI-verified.


The runner evidence route family has a dedicated `AIBRAIN_RUNNER_EVIDENCE_MAX_REQUEST_BODY_BYTES`
limit (15 MiB default), while ordinary API requests retain the 1 MiB default.
The conformance verifier still caps each artifact at 2 MiB, total artifact
bytes at 10 MiB, and artifact count at 64. A request-path prefix cannot extend
the larger body limit to similarly named unrelated routes.
