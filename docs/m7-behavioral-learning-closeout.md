# M7 — Behavioral Learning and Adaptation Governance

**Implementation status:** M7.1–M7.6 implementation is committed and verified on
`dev/tool-authorization-lifecycle` in Codespaces on 2026-11-24.

## Delivered scope

### M7.1 — Learning evidence and provenance
- Existing observations remain explicit, owner-scoped records.
- Every new adaptation proposal receives a default 30-day expiry (repository
  supports 1–365 days) and an immutable `proposed` event.
- Proposal events record the submitting source, expiry, and SHA-256 digest of
  the exact canonicalized proposal JSON.
- Evaluation records identify their source as `user_reported`, preserve the
  user-supplied evidence payload, metric, baseline, observed value, and
  confidence.

### M7.2 — Outcome evaluation
- Owners may record `improved`, `no_change`, `regressed`, or
  `inconclusive` outcomes against a named metric.
- Baseline and observed values must be finite numbers; confidence is bounded
  from 0.0 to 1.0.
- Evaluation is allowed only while the owner has an approved adaptation.
- Evaluation and governance records are immutable after insertion.

### M7.3 — Explicit governance lifecycle
- New proposals start as `pending`.
- Allowed transitions: pending → approved/rejected; approved →
  suspended/revoked; suspended → approved/revoked.
- Pending, approved, and suspended proposals expire at their deadline.
- Rejected, revoked, and expired states are terminal.
- Every proposal, decision, suspension, revocation, expiry, and evaluation
  creates an immutable owner-scoped event.
- Decision reasons are retained with their events.

### M7.4 — Owner control and rollback boundary
- Only the authenticated owner can review, approve, reject, suspend, or revoke
  their own proposals.
- Suspension is the governance rollback/pause control; revocation is terminal.
- Approval is a recorded owner decision only. It does not apply settings,
  change model behavior, grant permissions, or execute tools.
- No learning record can modify Phase 1 tool authorization, passkey approval,
  memory consent, or planning execution boundaries.

### M7.5 — Persistence and account lifecycle
- Migration 22 adds immutable adaptation-event and evaluation ledgers and
  proposal expiry.
- SQLite triggers independently enforce owner matching, the adaptation
  transition graph, approved-and-unexpired evaluation, and immutable history.
- Adaptations created before M7 retain a null expiry for compatibility; only
  new proposals receive the M7 default deadline.
- Account erasure removes evaluations and event history as part of the
  existing user-data deletion transaction.

### M7.6 — Regression coverage
- Added lifecycle, expiry, transition, owner isolation, evaluation gating,
  immutable history, migration version, and account-erasure coverage.

## API additions

- `GET /api/v1/personal/learning/adaptations/{id}/events`
- `GET /api/v1/personal/learning/adaptations/{id}/evaluations`
- `POST /api/v1/personal/learning/adaptations/{id}/evaluations`

The existing adaptation PATCH endpoint now accepts an optional `reason`
field and enforces the transition graph.

## Current limitations

- Outcomes are manually reported by the owner; no automatic event telemetry
  or causal evaluation is claimed.
- There is no automated model training, reinforcement learning, or
  self-modifying behavior.
- Proposal payloads remain descriptive JSON. Approval is not a deployment
  mechanism and does not cause an adaptation to take effect.
- There is no cross-device learning synchronization or production analytics
  pipeline.
- Evaluation confidence is a user-provided assessment, not a statistically
  calibrated probability.

## Verification

Run in Codespaces:

```bash
git pull --ff-only
python -m compileall -q backend tests scripts

pytest -q tests/test_learning_governance.py \
  tests/test_milestones_foundation.py

pytest -q
python -m pip check
```

**Verified result (2026-11-24):** focused tests `62 passed, 1 warning`; full
suite `785 passed, 1 warning`; `python -m compileall -q backend tests scripts`
passed; `python -m pip check` reported no broken requirements. The remaining
warning is Starlette's deprecation notice for using `httpx` with
`starlette.testclient`. Do not merge this development branch into `main`
without explicit approval.
