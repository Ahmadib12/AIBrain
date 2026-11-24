# M8 — Agent Lifecycle and Controlled Orchestration

**Status:** M8.1 and M8.2 are implemented and verified in Codespaces. M8.2 verification: 805 tests passed, compilation passed, and `pip check` reported no broken requirements (2026-11-24). M8.3–M8.6 control-plane implementation is committed to `dev/tool-authorization-lifecycle`; the new focused tests and full suite still require Codespaces verification.

## Objective

Introduce owner-controlled agent identities, lifecycle management, capability boundaries, task tracking, bounded coordination, and auditable recovery foundations. M8 creates the control plane only. It does not introduce autonomous execution or grant agents access to tools, memory, providers, devices, or external systems.

## Security invariants

1. Every agent belongs to exactly one active user account. Every read and mutation is scoped to the authenticated owner.
2. Agent existence, registration, or `active` status never grants a capability or authorizes execution.
3. Capability grants are explicit, owner-issued, narrow, revocable, and independently checked. A grant is not proof that a corresponding executor exists.
4. An agent cannot grant, expand, or transfer its own capabilities. Agent-to-agent delegation cannot exceed the delegator's effective owner-issued grants; M8 coordination records do not themselves delegate authority.
5. Task assignment is not execution authorization. Task records are advisory lifecycle records until a separately authorized executor exists.
6. Any future consequential tool call must use the existing tool gateway, request confirmation, passkey policy, dispatch contract, and reconciliation lifecycle. No M8 endpoint bypasses these controls.
7. Personal-memory access remains subject to the existing owner consent ledger and request-level opt-in. Agent status or capability labels cannot bypass memory consent.
8. Owner-facing event history is append-only during normal operation. Account erasure is the only permitted cascade-deletion boundary.
9. Unknown execution outcomes must never be represented as success. Recovery is explicit and auditable.
10. No agent is automatically activated, assigned work, or given permissions by registration.

## Workstreams and acceptance criteria

### M8.1 — Identity, registration, and ownership
- Stable opaque agent IDs; bounded names and descriptions; validated JSON metadata.
- Owner-scoped listing and retrieval; cross-owner access returns not-found.
- Immutable registration and lifecycle events with actor, event type, timestamp, and safe details.
- Database constraints/triggers enforce active-owner and owner-matching invariants.

### M8.2 — Lifecycle management
- States: `draft`, `active`, `suspended`, `terminated`.
- Allowed transitions: draft → active/terminated; active → suspended/terminated; suspended → active/terminated; terminated is terminal.
- Activation and resumption are explicit owner decisions. Termination is irreversible.
- Suspension prevents new task assignment; it does not silently erase grants or task history.

### M8.3 — Capability and permission boundaries
- Capability grants are separate owner-scoped records with explicit grant/revoke events and optional expiry.
- Only the owner may grant or revoke. Agents cannot mutate grants.
- No wildcard or implicit inheritance. Unknown capability names are rejected by a versioned allow-list.
- Grants are descriptive policy records only in this milestone; no tool executor is wired to them.
- A grant cannot override tool risk, confirmation, passkey, memory consent, or account status.

### M8.4 — Task assignment and lifecycle
- Owner-created tasks bind to one owner-owned agent and carry bounded goal/context metadata, deadline, and an explicit capability ceiling.
- Task ceiling must be a subset of the agent's currently active owner-issued grants.
- Assignment requires an active agent. Suspended/terminated agents cannot receive new tasks.
- Task states are explicit and monotonic; completion/failure/cancellation are owner- or future trusted-runner-reported facts, never inferred from agent status.
- No task endpoint executes code or calls providers/tools.

### M8.5 — Controlled coordination
- Coordination is represented as bounded, owner-scoped messages/references between agents owned by the same user.
- Sender/recipient identity and task association are validated; payloads are size/depth/sensitive-value checked.
- Messages are informational and cannot create grants, authorize tools, alter task state, or impersonate owner approval.
- Cross-owner communication and implicit capability delegation are prohibited.

### M8.6 — Audit, recovery, and failure handling
- Append-only agent, grant, task, and coordination event ledgers.
- Explicit task cancellation and stale/expired task reconciliation; unknown outcomes remain unknown.
- Account erasure removes agent-owned records transactionally after tombstoning the owner.
- Tests cover owner isolation, invalid transitions, grant/task ceiling enforcement, expiry, immutability, replay, and account erasure.

## M8.2 is closed. M8.3–M8.6 have been implemented together on the development branch as one integrated control-plane slice:

- **M8.3:** versioned capability allow-list, owner-issued immutable grants, expiry, append-only revocation, and grant checks when tasks are created.
- **M8.4:** owner-created tasks with immutable definitions, grant-ceiling enforcement, explicit state transitions, cancellation, and deadline expiry.
- **M8.5:** bounded informational messages between active agents belonging to the same owner, with optional task-recipient binding.
- **M8.6:** immutable task/control-event ledgers, explicit expired-task reconciliation, database ownership/immutability triggers, and account-erasure coverage.

The combined implementation is not verified until the focused tests, complete suite, compilation, dependency check, and migration/account-erasure tests pass in Codespaces.

## API shape (implemented; verification pending)

All endpoints are authenticated and owner-scoped:

- `POST /api/v1/agents/{agent_id}/capabilities`, `GET /api/v1/agents/{agent_id}/capabilities`, `DELETE /api/v1/agents/{agent_id}/capabilities/{grant_id}`
- `GET /api/v1/agent-capabilities/catalog`
- `POST /api/v1/agents/{agent_id}/tasks`, `GET /api/v1/agents/{agent_id}/tasks`
- `GET /api/v1/agent-tasks/{task_id}`, `PATCH /api/v1/agent-tasks/{task_id}/lifecycle`, `GET /api/v1/agent-tasks/{task_id}/events`
- `POST /api/v1/agents/{agent_id}/messages`, `GET /api/v1/agents/{agent_id}/messages`
- `GET /api/v1/agents/{agent_id}/control-events`
- `POST /api/v1/agent-tasks/reconcile-expired`

Task lifecycle transitions and message creation are owner-authored records; they do not represent execution telemetry or proof of agent activity. The capability catalog is descriptive and `execution_enabled` is always false.

## Explicit non-goals

- No autonomous agent loop, planner-to-agent execution, provider invocation, tool execution, shell/browser access, or device control.
- No automatic agent creation, activation, task assignment, permission escalation, or agent-to-agent authority transfer.
- No claim of multi-agent intelligence merely because coordination records exist.
- No vector memory access, cross-account sharing, production distributed scheduler, or hostile-code sandbox.
- No changes to the existing Phase 1 tool authorization boundary or M6/M7 owner-control guarantees.

## Verification gate

M8 is not complete until focused agent tests, the full test suite, compilation, dependency checks, and migration/account-erasure tests pass in Codespaces. Keep all work on `dev/tool-authorization-lifecycle`; do not merge to `main` without explicit approval.
