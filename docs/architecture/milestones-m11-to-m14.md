# AIBrain M11–M14: secure action, digital twin, provider policy, and bounded planning

Status: implementation increment on `dev/tool-authorization-lifecycle`.
This document records the delivered foundations and the remaining production
requirements. A green unit suite does not imply production providers, remote
actions, Android/desktop clients, or autonomous operation are enabled.

## M11 — Secure external-action ecosystem

`ExternalToolAdapterRegistry` now requires composition-time
`ExternalActionReadinessEvidence` for adapters explicitly marked
`production_provider = True`. Evidence binds provider ID, adapter ID/version,
provider account scope, verifier ID, the pinned HTTPS transport identifier,
and named conformance-suite identity/version. Provider verification, transport
conformance, provider-enforced idempotency, and read-only outcome lookup
conformance must all be explicitly reported as passing.

This is an additional fail-closed registration gate, not certification.
`ExternalToolDispatcher` still requires the persisted, exact-scope,
operator-approved adapter certification and the owner's one-time passkey
authorization. It records unknown outcomes and never retries automatically.
No production state-changing adapter is registered or activated. The readiness
evidence is trusted only because it is supplied by application composition;
untrusted API requests cannot register adapters or provide this evidence.

Files: `backend/app/tools/external_action_readiness.py`,
`backend/app/tools/dispatcher.py`, and
`tests/test_external_action_readiness.py`.

## M12 — Personal memory and digital twin

`GET /api/v1/personal/digital-twin` returns a read-only, bounded projection of
explicit owner-approved `preference`, `goal`, and `project` memory records.
It excludes transient `context` records and does not infer facts from
observations or behavior. Each record retains source, confidence, and timestamps.

The endpoint requires active memory consent. A single joined repository query
reads the active consent generation and its records together, avoiding a
revocation race between a separate consent check and memory listing. Existing
owner review, correction, deletion, export, retention, and consent-revocation
controls remain authoritative.

Files: `backend/app/intelligence/digital_twin.py`,
`backend/app/persistence/memory.py`,
`backend/app/api/v1/personal.py`, and
`tests/test_digital_twin.py` / `tests/test_memory_core.py`.

## M13 — Multi-provider independence and policy-aware routing

`ProviderProfileRegistry` and `ProviderRoutingPolicy` introduce trusted,
composition-time profiles for provider execution location, data classes,
capabilities, cost tier, data residency, and provider version. A caller may
supply neither profiles nor trusted routing requirements through chat request
JSON. The router applies requirements only when trusted server-side
`ProviderRoutingRequirements` are passed to it. It fails closed if policy
requirements are supplied without a trusted policy or if no candidate
satisfies them. The provider runtime builder accepts a trusted profile registry
for deployment composition.

This extends the provider-neutral router; it does not add a real cloud provider
or local inference runtime. No provider credentials are required or stored.
Profiles must be reviewed against actual provider contracts and deployment
configuration before use.

Files: `backend/app/providers/policy.py`,
`backend/app/providers/router.py`, `backend/app/providers/runtime.py`, and
`tests/test_provider_policy.py`.

## M14 — Bounded autonomous planning

`PlanRunProposalBridge` validates a deterministic `PlanningResult` and maps
every capability-bearing plan task exactly once to a registered read-only tool
action. It rejects unresolved clarification, authorization-required plans,
missing capabilities, unplanned actions, capability mismatches, duplicate
mappings, and unsupported task mappings.

`POST /api/v1/agent-tasks/{task_id}/plan-runs` creates a durable M9 run
proposal. The existing M9 repository independently checks live task status,
agent capability ceilings, tool risk, input schema, and contract fingerprint.
The endpoint returns explicit `execution_authorized: false` and
`execution_started: false`. The owner must separately authorize and execute
through the existing M9 lifecycle. Consequential actions, automatic execution,
and automatic retries remain unavailable.

Files: `backend/app/intelligence/planning/agent_bridge.py`,
`backend/app/api/v1/agent_execution.py`, and
`tests/test_plan_run_proposal_bridge.py`.

## Verification

Run focused tests first, then the complete suite:

```bash
python -m compileall -q backend tests scripts

pytest -q tests/test_external_action_readiness.py \
  tests/test_digital_twin.py tests/test_memory_core.py \
  tests/test_agent_control_plane.py tests/test_provider_policy.py \
  tests/test_plan_run_proposal_bridge.py \
  tests/test_intelligence_planning_contracts.py \
  tests/test_intelligence_planning_engine.py \
  tests/test_intelligence_planning_evaluation.py \
  tests/test_external_tool_dispatcher.py \
  tests/test_agent_execution.py

pytest -q
python -m pip check
git status --short
```

## Not included / production blockers

- No real state-changing external provider adapter is registered.
- No API endpoint accepts caller-supplied adapter readiness evidence.
- Production provider evidence must be generated from real provider-specific
  verification and independently reviewed conformance runs, not hand-authored
  booleans.
- Provider profiles are trusted deployment configuration and must be wired by
  the production composition root before sensitive routing can rely on them.
- No real cloud provider SDK, local inference runtime, or model download flow
  is enabled.
- Digital-twin records are explicit saved memory, not a complete inferred
  personal model; semantic retrieval and cross-device synchronization remain
  separate work.
- Plans remain proposals. Human authorization, current task grants, tool
  certification, passkey policy, and M9 execution checks remain mandatory.
- Android/desktop native clients, distributed synchronization, and AGLI live
  calling are not delivered by these backend milestones.
