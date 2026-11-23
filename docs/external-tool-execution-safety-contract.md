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

The binding is not yet connected to a dispatcher or to passkey-authorized
claims. It is a persistence primitive and test target only. Account deletion
continues to cascade through owner-scoped records. The conformance tests are
in `tests/test_tool_execution_bindings.py`.

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

Remaining steps are to persist the immutable dispatch binding, implement
provider-backed lookup/reconciliation, gather sandbox evidence for an actual
provider's guarantees, and only then consider one narrowly scoped
state-changing adapter behind an explicit feature gate.
