# M9 — Autonomous Intelligence and Governed Execution

**Status:** Integrated implementation committed on `dev/tool-authorization-lifecycle`; Codespaces verification is pending. This milestone is not closed until focused tests, the complete suite, compilation, migration/account-erasure checks, and dependency checks pass.

## Objective

Connect the M5 planning foundation and M8 agent control plane to a narrowly governed execution lifecycle. An agent run is a bounded, persisted proposal that is explicitly authorized by the account owner and revalidated immediately before execution.

M9 establishes the execution control plane and a first read-only runtime path. It does not claim unrestricted autonomy or production-ready external integrations.

## Security invariants

1. An agent must be active, the task must be live, and both must belong to the authenticated owner when a run is proposed, authorized, and executed.
2. A run definition is immutable and identified by a SHA-256 digest over its canonical action list.
3. Creating a run never executes a tool. A separate owner-authenticated authorization request is required.
4. Authorization binds to the persisted run digest. The digest, current agent status, task status/deadline, required capability grants, and tool contract fingerprints are rechecked before execution.
5. Capability requirements on an action must be inside the task's capability ceiling and backed by current, unexpired, unrevoked owner-issued grants.
6. This M9 runtime executes only registered `READ_ONLY` tool contracts. `STATE_CHANGE` and `CONSEQUENTIAL` actions are rejected; agent-run authorization cannot replace tool confirmation or passkey approval.
7. Tool execution is delegated to the existing `ToolExecutionGateway`; it does not create an alternate tool execution boundary.
8. A run executes steps sequentially. A failed step stops the run, remaining steps are skipped, and automatic retry is disabled.
9. Run and step definitions are immutable; run events are append-only outside account erasure. All records are owner-scoped.
10. Agent run completion is not equivalent to owner acceptance or task completion. M8 task lifecycle remains separately controlled.

## M9.1 — Bounded run proposals

- Owner creates a run against an existing assigned/in-progress task.
- Each run contains 1–10 ordered read-only tool actions.
- Arguments are validated against the registered tool contract.
- Tool contract fingerprints and the canonical plan digest are persisted.
- Run and step definitions are immutable.

## M9.2 — Explicit owner authorization

- New runs begin in `proposed`.
- The owner must explicitly authorize the persisted digest.
- Agent activation, task assignment, or capability grants do not authorize a run.
- Authorization fails if the agent/task is no longer live, the run expires, or a required grant is revoked/expired.

## M9.3 — Governed execution

- Only `READ_ONLY` contracts are accepted.
- The current contract fingerprint and risk are revalidated at execution.
- Execution uses the existing tool gateway and persists the associated tool-request ID and result.
- State-changing and consequential actions remain unavailable to the agent runtime.

## M9.4 — Failure and audit

- Run lifecycle: `proposed → authorized → running → completed/failed`; unstarted runs may be cancelled.
- Step outcomes and lifecycle events are persisted.
- A failed step halts the run; no automatic retry is attempted.
- Run state transitions require matching immutable events at the database boundary.
- Account erasure cascades run, step, and event records after owner tombstoning.

## API

- `POST /api/v1/agent-tasks/{task_id}/runs`
- `GET /api/v1/agent-runs/{run_id}`
- `GET /api/v1/agent-runs/{run_id}/events`
- `POST /api/v1/agent-runs/{run_id}/authorize`
- `POST /api/v1/agent-runs/{run_id}/execute`
- `POST /api/v1/agent-runs/{run_id}/cancel`

## Current runtime limits

- The registered runtime currently implements the read-only `echo` tool only.
- No external search, browser, calendar, notes, filesystem, shell, or device adapter is enabled by this milestone.
- No state-changing or consequential action is executable by an agent.
- This is not a hostile-code sandbox, distributed scheduler, or production multi-agent runtime.
- A crash during an in-flight run leaves a non-terminal run for inspection; this milestone does not automatically replay it.
- M5 planning remains advisory; this run API accepts an explicit bounded action list and does not claim model-generated plans are trusted or executable.

## Verification gate

Run in Codespaces:

```bash
git pull --ff-only
python -m compileall -q backend tests scripts
pytest -q tests/test_agent_execution.py
pytest -q tests/test_agent_control_plane.py
pytest -q tests/test_agent_identity.py
pytest -q tests/test_agent_lifecycle.py
pytest -q tests/test_milestones_foundation.py
pytest -q
python -m pip check
```

Do not mark M9 complete until these checks pass and account-erasure/migration coverage is confirmed. Keep all work on `dev/tool-authorization-lifecycle`; do not merge to `main` without explicit approval.
