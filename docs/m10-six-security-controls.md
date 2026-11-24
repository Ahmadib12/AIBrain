# M10 governed integration security — implementation boundary

This document records the six security workstreams as one coordinated security
boundary. It is intentionally explicit about what is implemented and what
remains disabled.

## 1. Encrypted credential vault

- Provider credential material is encrypted with AES-256-GCM.
- The 32-byte key is supplied through `AIBRAIN_INTEGRATION_VAULT_KEY_B64`
  (or an equivalent deployment secret manager mapping); it is never generated
  by the application or stored in SQLite.
- Associated data binds ciphertext to owner, connection, integration, and
  opaque secret reference.
- SQLite stores nonce and ciphertext only. API connection representations
  omit the secret reference and credential payload.
- Missing or invalid key material makes the vault unavailable and blocks
  trusted activation.

## 2. Trusted provider verification and activation

- Provider verifiers are registered only by application composition.
- Owner API consent creates a pending connection and exact pending scopes.
- Only the internal lifecycle service can move a connection to active, after
  verifier success and vault persistence.
- Database triggers require a matching encrypted vault row before activation.
- No client-supplied `verified`, token, or secret-reference field can activate
  a connection. No public activation endpoint exists.
- No provider verifier is registered by default; connections therefore remain
  pending until a provider-specific verifier is implemented and reviewed.

## 3. Expiry, rotation, revocation, and race safety

- Connection and scope expiry are checked at runtime and can be reconciled by
  `IntegrationConnectionRepository.expire_due()`.
- Revocation, disconnect, and terminal expiry destroy the encrypted vault row
  through a database trigger.
- Provider credential rotation must pass through the trusted lifecycle service;
  rotation never writes credential material to audit events.
- Read-only runtime rechecks exact owner grants immediately before adapter
  dispatch and after completion. A result is discarded if authority changes
  while the adapter is running. Revocation cannot retroactively cancel an
  already-issued network request.

## 4. M9 agent-run binding boundary

- M9 agent runs continue to accept only tools in the existing trusted tool
  registry. Integration catalog tools are not inserted into that registry.
- An integration tool ID therefore cannot be smuggled into an ordinary agent
  run or executed through the synchronous M9 gateway.
- Full integration-aware agent plans require a dedicated asynchronous
  orchestrator that persists and revalidates connection ID, integration ID,
  manifest version, contract fingerprint, and exact scopes per step. That
  orchestrator is not enabled in this commit; the current boundary is fail
  closed rather than silently bypassing the binding requirement.

## 5. Execution-time authority

- The integration runtime resolves tool IDs only through the trusted manifest.
- It permits READ_ONLY contracts only, validates arguments and output schemas,
  applies timeout and serialized output limits, rejects credential-like output
  keys, and checks active exact-scope grants before and after adapter execution.
- No state-changing or consequential integration operation is accepted here.
  Those operations remain in the existing M9/M5 authorization, passkey,
  certification, idempotency, and reconciliation workflows.

## 6. Conformance, audit, and provider egress

- Provider verification audit events contain verifier identity, a
  non-reversible provider-subject fingerprint, granted scopes, and expiry only;
  they never contain credentials.
- Credential-like output names are rejected, including common camelCase and
  punctuation variants.
- `ProviderEgressPolicy` provides strict HTTPS host allowlisting and rejects
  IP-literal, private, loopback, link-local, reserved, and otherwise non-global
  DNS answers. A real provider transport must pin validated DNS answers to its
  socket and disable redirects; the helper does not itself perform HTTP.
- No real provider adapter is registered by default. A provider-specific
  conformance suite, transport-level DNS pinning/redirect tests, secret
  rotation tests, and external-provider verification tests are still required
  before any production connector is enabled.

## Operational configuration

Generate and store a 32-byte random key in the deployment secret manager, then
provide its Base64 encoding as `AIBRAIN_INTEGRATION_VAULT_KEY_B64`. Never put
the key in source control, logs, issue comments, or chat. Back it up using the
deployment's key-management policy; losing it makes existing ciphertext
unreadable. Key-version migration and re-encryption for key rotation must be
planned before changing the deployment key.

## Status

The vault, activation database guard, verifier boundary, connection expiry
reconciliation, revocation-driven ciphertext deletion, runtime authority
rechecks, credential-output filtering, and egress validation primitives are
implemented. Integration-aware M9 asynchronous orchestration and real provider
adapters remain intentionally disabled. M10 is not complete until those
remaining controls and provider-specific conformance tests are implemented.
