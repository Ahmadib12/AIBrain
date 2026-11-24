# M8 — Agent Lifecycle and Controlled Orchestration

**Status:** Architecture contract approved. M8.1 owner-scoped identity registration is implemented, verified in Codespaces (795 tests passed; compilation and dependency checks passed), and pushed to `dev/tool-authorization-lifecycle` as `b9e9243`. M8.2–M8.6 are the remaining implementation milestones.

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

## Remaining delivery sequence

The remaining M8 work is split into five independently verifiable milestones and must be delivered in dependency order:

1. **M8.2 — Lifecycle management:** implement the explicit agent state machine and immutable lifecycle events.
2. **M8.3 — Capability and permission boundaries:** implement owner-controlled, expiring/revocable grants and enforce the versioned capability allow-list. Grants remain non-executable policy records.
3. **M8.4 — Task assignment and lifecycle:** implement owner-created tasks, grant-ceiling validation, explicit task states, cancellation, and expiry. Task records remain non-executable.
4. **M8.5 — Controlled coordination:** implement bounded same-owner agent messages/references with strict sender, recipient, task, payload, and ownership validation. Coordination cannot convey authority.
5. **M8.6 — Audit, recovery, and failure handling:** complete append-only ledgers, stale/unknown-outcome reconciliation, transactional account-erasure coverage, and cross-milestone security verification.

Each milestone must add focused tests and migration/account-erasure coverage where applicable. After each milestone, run compilation, focused tests, the full test suite, and dependency checks in Codespaces. Update this architecture and `docs/IMPLEMENTATION_STATUS.md` only after the corresponding implementation and verification evidence exists. M8.6 closes M8 only after the complete verification gate below passes.

## API shape (target)

All routes are authenticated and owner-scoped under `/api/v1/agents`:

- `POST /agents`, `GET /agents`, `GET /agents/{agent_id}`
- `PATCH /agents/{agent_id}/lifecycle`
- `GET /agents/{agent_id}/events`
- `POST /agents/{agent_id}/capabilities`, `GET /agents/{agent_id}/capabilities`, `DELETE /agents/{agent_id}/capabilities/{grant_id}`
- `POST /agents/{agent_id}/tasks`, `GET /agents/{agent_id}/tasks`
- `GET /tasks/{task_id}`, `PATCH /tasks/{task_id}/lifecycle`
- `POST /agents/{agent_id}/messages`, `GET /agents/{agent_id}/messages`

The final route set may be narrowed to avoid duplicate or ambiguous resource ownership. Responses must use the centralized public error envelope.

## Explicit non-goals

- No autonomous agent loop, planner-to-agent execution, provider invocation, tool execution, shell/browser access, or device control.
- No automatic agent creation, activation, task assignment, permission escalation, or agent-to-agent authority transfer.
- No claim of multi-agent intelligence merely because coordination records exist.
- No vector memory access, cross-account sharing, production distributed scheduler, or hostile-code sandbox.
- No changes to the existing Phase 1 tool authorization boundary or M6/M7 owner-control guarantees.

## Verification gate

M8 is not complete until focused agent tests, the full test suite, compilation, dependency checks, and migration/account-erasure tests pass in Codespaces. Keep all work on `dev/tool-authorization-lifecycle`; do not merge to `main` without explicit approval.
