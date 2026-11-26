# PostgreSQL schema parity inventory

Status: **partial PostgreSQL schema port; not application-selectable and not parity-complete**.

Source of truth: `backend/app/persistence/database.py`, method
`Database.migrate()`, at the commit where this inventory was prepared.
The SQLite migration stream contains versions **1–45**. The inventory below
counts distinct `CREATE TABLE`, `CREATE INDEX` / `CREATE UNIQUE INDEX`,
and `CREATE TRIGGER` declarations across that stream; repeated declarations
used to rebuild or replace triggers are counted once by name.

| SQLite object | Distinct names |
|---|---:|
| Tables | 56 |
| Indexes | 60 |
| Triggers | 139 |
| Migration versions | 45 |

These counts are an audit baseline, not proof that PostgreSQL has equivalent
objects. PostgreSQL migrations 1–2 cover identity/session, memory, observations,
adaptations, audit events, tool requests, WebAuthn and tool authorization
foundations. PostgreSQL migrations 3–7 cover tool execution, external adapter
evidence, trusted runner attestations and operator audit (SQLite migrations
9–15). PostgreSQL migrations 8–11 add dispatch recovery, certification-bound
lookup authorization, account-erasure guards and execution reconciliation
(SQLite migrations 16–20). PostgreSQL migrations 12–13 port memory consent and memory binding plus learning
adaptation history, lifecycle transitions and evaluations (SQLite migrations
21–22). PostgreSQL migrations 14–18 now port agent identity/lifecycle, capability
grants and revocations, tasks, messages, control events, bounded runs, steps,
and immutable run history (SQLite migrations 23–27). PostgreSQL still lacks
SQLite migrations 28–45, complete repository compatibility, and shared
multi-instance acceptance. The
stream must not be described as schema-complete or application-ready until
every required invariant below is ported and tested.

## Migration domains

| SQLite versions | Domain to port |
|---|---|
| 1–11 | Identity, sessions, memory/observations/adaptations, tool requests, WebAuthn/passkeys, tool authorization, execution attempts/bindings, dispatch audit |
| 12–15 | External adapter certification/evidence, trusted runner keys/attestations, operator audit (PostgreSQL migrations 4–7) |
| 16–20 | Dispatch recovery/lookup authorization and execution reconciliation (PostgreSQL migrations 8–11) |
| 21–22 | Memory consent lifecycle, learning adaptation events and evaluations (PostgreSQL migrations 12–13) |
| 23–27 | Agent identity/events, capability grants and revocations, tasks/messages/control events, runs/steps/events |
| 28–31 | Integration connections/grants/events/secrets, agent-run integration bindings and dispatches |
| 32–35 | Capability-table transition and device/session schema evolution |
| 36–42 | Device security audit, device lifecycle guards, session/device binding and audit, key rotation and lost-device recovery |
| 43–45 | Recovery notification outbox, terminal failure/dead-letter state, operator redrive audit, claim fencing, recovery-abuse windows |

The exact SQL in each numbered SQLite migration remains authoritative; the
domain grouping above is a navigation aid, not a substitute for migration
review.

## Table inventory (56)

```text
adaptations
agent_capability_grants
agent_capability_grants_new
agent_capability_revocations
agent_capability_revocations_new
agent_control_events
agent_events
agent_messages
agent_run_events
agent_run_integration_bindings
agent_run_integration_dispatches
agent_run_steps
agent_runs
agent_task_events
agent_tasks
agents
audit_events
device_auth_challenges
device_key_rotation_challenges
device_security_events
devices
external_adapter_certification_revocations
external_adapter_certifications
external_adapter_evidence_artifacts
external_adapter_evidence_attestations
external_adapter_evidence_packages
integration_connection_events
integration_connection_grants
integration_connections
integration_secrets
learning_adaptation_events
learning_evaluations
memory_consents
memory_items
observations
schema_migrations
security_notification_operator_events
security_notification_outbox
security_operator_audit_events
security_recovery_abuse_windows
session_security_events
sessions
tool_authorizations
tool_dispatch_audit_events
tool_dispatch_lookup_authorizations
tool_dispatch_recovery_events
tool_execution_attempts
tool_execution_bindings
tool_execution_reconciliation_events
tool_requests
trusted_runner_key_revocations
trusted_runner_keys
users
webauthn_challenges
webauthn_credentials
webauthn_recovery_codes
```

## Index inventory (60)

```text
idx_adaptation_user
idx_agent_control_events_owner_agent
idx_agent_events_owner_agent
idx_agent_grants_owner_agent
idx_agent_messages_owner_recipient
idx_agent_run_events_owner_run
idx_agent_run_integration_bindings_owner
idx_agent_run_integration_dispatches_owner
idx_agent_run_steps_owner_run
idx_agent_runs_owner_task
idx_agent_runs_status_expiry
idx_agent_task_events_owner_task
idx_agent_tasks_owner_agent
idx_agents_owner_created
idx_device_auth_challenges_expiry
idx_device_key_rotation_expiry
idx_device_key_rotation_recovery_code
idx_device_security_events_owner_time
idx_devices_owner_status
idx_evidence_attestation_key
idx_external_adapter_certification_lookup
idx_external_adapter_certification_revocations
idx_external_adapter_evidence_binding
idx_integration_connection_events_owner
idx_integration_connections_owner
idx_integration_grants_owner
idx_integration_secrets_owner
idx_learning_adaptation_events_owner
idx_learning_evaluations_owner
idx_memory_active_consent
idx_memory_consent_user_history
idx_memory_items_consent
idx_memory_user
idx_observation_user
idx_security_notification_claim_token
idx_security_notification_operator_events_notification
idx_security_notification_outbox_ready
idx_security_operator_audit_actor
idx_security_operator_audit_target
idx_security_recovery_abuse_window
idx_session_security_events_owner_time
idx_session_security_events_session
idx_sessions_audit_ref
idx_sessions_device_active
idx_sessions_user
idx_tool_authorizations_user
idx_tool_dispatch_audit_user
idx_tool_dispatch_lookup_authorizations_request
idx_tool_dispatch_recovery_request
idx_tool_execution_attempts_status_claimed
idx_tool_execution_attempts_user
idx_tool_execution_bindings_user
idx_tool_execution_reconciliation_request
idx_tool_request_user
idx_trusted_runner_key_revocations
idx_trusted_runner_keys_runner
idx_webauthn_challenges_expiry
idx_webauthn_challenges_user
idx_webauthn_credentials_user
idx_webauthn_recovery_codes_user
```

## Trigger inventory (139)

```text
audit_device_activation
audit_device_enrollment
audit_device_key_registration
audit_device_revocation
audit_device_session
audit_session_created
audit_session_expired
audit_session_revoked
enqueue_device_recovery_notification
erase_integration_secret_on_terminal_connection
prevent_adaptation_for_deleted_user
prevent_agent_control_event_delete
prevent_agent_control_event_update
prevent_agent_delete
prevent_agent_event_delete
prevent_agent_event_update
prevent_agent_grant_delete
prevent_agent_grant_update
prevent_agent_identity_update
prevent_agent_message_delete
prevent_agent_message_update
prevent_agent_revocation_delete
prevent_agent_revocation_update
prevent_agent_run_definition_update
prevent_agent_run_delete
prevent_agent_run_event_delete
prevent_agent_run_event_update
prevent_agent_run_integration_binding_delete
prevent_agent_run_integration_binding_update
prevent_agent_run_integration_dispatch_delete
prevent_agent_run_integration_dispatch_identity_update
prevent_agent_run_integration_dispatch_terminal_update
prevent_agent_run_step_definition_update
prevent_agent_run_step_delete
prevent_agent_task_content_update
prevent_agent_task_delete
prevent_agent_task_event_delete
prevent_agent_task_event_update
prevent_agent_task_identity_update
prevent_agent_termination_reversal
prevent_client_session_audit_ref
prevent_device_for_inactive_user
prevent_device_identity_mutation
prevent_device_key_rotation_without_proof
prevent_device_public_key_replacement
prevent_device_security_event_delete
prevent_device_security_event_update
prevent_evidence_attestation_delete
prevent_evidence_attestation_update
prevent_external_adapter_certification_delete
prevent_external_adapter_certification_update
prevent_external_adapter_evidence_artifact_delete
prevent_external_adapter_evidence_artifact_update
prevent_external_adapter_evidence_delete
prevent_external_adapter_evidence_update
prevent_external_adapter_revocation_delete
prevent_external_adapter_revocation_update
prevent_integration_connection_event_delete
prevent_integration_connection_event_update
prevent_integration_grant_scope_update
prevent_integration_secret_delete
prevent_integration_secret_identity_update
prevent_learning_adaptation_event_delete
prevent_learning_adaptation_event_update
prevent_learning_evaluation_delete
prevent_learning_evaluation_update
prevent_memory_consent_delete
prevent_memory_consent_for_deleted_user
prevent_memory_consent_identity_update
prevent_memory_consent_policy_update_after_revoke
prevent_memory_consent_reactivation
prevent_memory_for_deleted_user
prevent_observation_for_deleted_user
prevent_runner_key_revocation_delete
prevent_runner_key_revocation_update
prevent_security_notification_operator_event_update
prevent_security_operator_audit_delete
prevent_security_operator_audit_update
prevent_session_audit_ref_replacement
prevent_session_for_deleted_user
prevent_session_identity_mutation
prevent_session_security_event_delete
prevent_session_security_event_update
prevent_session_unrevocation
prevent_tool_authorization_for_deleted_user
prevent_tool_dispatch_audit_delete
prevent_tool_dispatch_audit_update
prevent_tool_dispatch_lookup_authorization_delete
prevent_tool_dispatch_lookup_authorization_update
prevent_tool_dispatch_recovery_delete
prevent_tool_dispatch_recovery_update
prevent_tool_execution_attempt_for_inactive_user
prevent_tool_execution_binding_insert_unclaimed
prevent_tool_execution_binding_update
prevent_tool_execution_reconciliation_delete
prevent_tool_execution_reconciliation_update
prevent_tool_request_for_deleted_user
prevent_trusted_runner_key_delete
prevent_trusted_runner_key_update
prevent_webauthn_challenge_for_deleted_user
prevent_webauthn_credential_for_deleted_user
prevent_webauthn_recovery_code_for_deleted_user
require_active_connection_for_active_grant
require_verified_integration_activation
validate_agent_control_event_insert
validate_agent_event_insert
validate_agent_grant_insert
validate_agent_insert
validate_agent_message_insert
validate_agent_revocation_insert
validate_agent_run_event_insert
validate_agent_run_insert
validate_agent_run_integration_binding_insert
validate_agent_run_integration_binding_scopes
validate_agent_run_integration_dispatch_insert
validate_agent_run_integration_dispatch_transition
validate_agent_run_status_transition
validate_agent_run_step_insert
validate_agent_run_step_status_transition
validate_agent_status_transition
validate_agent_task_event_insert
validate_agent_task_insert
validate_agent_task_transition
validate_device_challenge_insert
validate_device_status_transition
validate_integration_connection_event_insert
validate_integration_connection_insert
validate_integration_grant_insert
validate_integration_secret_insert
validate_learning_adaptation_event
validate_learning_adaptation_transition
validate_learning_evaluation
validate_memory_consent_insert
validate_memory_consent_update
validate_session_device_binding
validate_tool_dispatch_audit_event
validate_tool_dispatch_lookup_authorization
validate_tool_dispatch_recovery_event
validate_tool_execution_reconciliation_event
```

## Security invariants requiring explicit PostgreSQL acceptance tests

1. **Account lifecycle and ownership:** deleted/inactive accounts cannot create
   sessions, memories, authorizations, devices, integrations, agents, or other
   owned records. Preserve owner isolation and account-erasure semantics.
2. **Credential and session safety:** WebAuthn challenge purpose/expiry/one-time
   use, recovery-code one-time use, session identity immutability, revocation,
   device binding, and session audit history.
3. **Tool execution safety:** one execution attempt per request, unique
   idempotency, immutable dispatch binding, authorized state transitions,
   immutable audit/reconciliation events, and safe unknown-outcome recovery.
4. **Evidence trust:** certification/evidence/attestation immutability,
   trusted-runner key lifecycle, revocation, and cryptographic binding.
5. **Memory and learning consent:** consent identity and policy immutability,
   revocation finality, valid adaptation transitions, and immutable evaluation
   history.
6. **Agent lifecycle:** immutable agent/task/run definitions, valid status
   transitions, termination finality, capability grant/revocation rules,
   scoped messages, and immutable event histories.
7. **Integration safety:** verified connection activation, grant scope binding,
   active connection requirements, secret protection/erasure, and run-bound
   integration dispatch authorization.
8. **Device recovery:** immutable device identity/key registration, proof-bound
   key rotation, single-use recovery code, session revocation, and durable audit.
9. **Notification operations:** transactional outbox enqueue, unique event
   binding, claim-token fencing, lease recovery, bounded retry/dead-letter,
   audited operator redrive, and account erasure.
10. **Abuse controls:** account and source-IP counters are atomic, privacy
    preserving, bounded by TTL/window, and fail closed when Redis is selected.

## Porting rules

- Keep SQLite as the only selectable application backend until every gate in
  `postgresql-shared-persistence.md` passes.
- Do not copy SQLite trigger bodies verbatim. Express invariants with PostgreSQL
  constraints, carefully designed trigger functions, and explicit repository
  transactions/row locks where appropriate.
- Preserve externally visible repository row shapes and domain error behavior.
- Every PostgreSQL migration must have a stable version/name, be transactional,
  restart-safe, and serialized by the advisory lock.
- Add PostgreSQL integration tests for each security invariant as its migration
  lands. Unit tests with fakes are not a substitute for a real PostgreSQL run.
- The next implementation batch should port the foundational identity, memory,
  WebAuthn, tool-request, authorization, and execution tables, then prove
  constraints and active-account guards before proceeding to later domains.
