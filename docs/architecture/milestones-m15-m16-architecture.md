# AIBrain M15 + M16: Unified Language Intelligence and Cross-Platform Assistant

Status: proposed architecture and implementation contract; not an implementation-completion claim.
Target branch: `dev/tool-authorization-lifecycle`.
Scope: coordinated delivery of M15 (Adaptive Global Language Intelligence) and M16 (Universal Cross-Platform Personal Assistant).

## 1. Executive decision

M15 and M16 are one coordinated programme with separate milestone acceptance gates. They share identity, authorization, provider routing, memory, event contracts, device capabilities, offline policy, evaluation, and observability.

The first release remains a **modular monolith**: the existing FastAPI backend owns identity, policy, orchestration, durable records, provider routing, and audit. Android and desktop are separate clients that use versioned APIs and typed events. Specialized language engines and device integrations sit behind replaceable contracts. Do not introduce microservices without a demonstrated operational need.

This document defines contracts and sequencing. It does not claim that speech, translation, local inference, telephony, device synchronization, Android, or desktop support currently exists.

## 2. Repository audit: verified current state

The audit was performed against `dev/tool-authorization-lifecycle`.

### Existing foundations to reuse

- FastAPI versioned API and application lifespan.
- SQLite migration/repository pattern, account identity, bearer sessions, passkey infrastructure, and owner-scoped data repositories.
- Provider-neutral `AIProvider` interface, registry, fallback executor, health monitor, mock provider, and trusted provider-routing policy.
- AGLI language metadata schemas and registry, with capability status kept separate from metadata registration.
- Central Intelligence Core, capability adapters, request context, bounded execution, decision traces, and planning.
- Consent-controlled personal memory and the read-only Digital Twin projection.
- Permission-gated agent proposals and execution lifecycle, integration vault, pinned transport, conformance evidence, and recovery boundaries.
- An SSE endpoint exists at `POST /api/v1/intelligence/process/stream`, but it currently yields one completed response event after the core finishes. It is not token streaming or a real-time media transport.

### Confirmed gaps

1. The AGLI registry currently contains metadata for English, Spanish, French, and Arabic. The language capability profiles are registered metadata; they do not prove that detection, translation, speech recognition, synthesis, or live translation works.
2. The AGLI adapter currently implements language lookup. No real translation, ASR, or TTS engine was found.
3. The only built-in AI provider is the deterministic mock provider. No production cloud SDK or local inference runtime is enabled.
4. The current provider interface is text-chat oriented. It needs explicit modality and streaming contracts before audio work can be routed safely.
5. The intelligence streaming route emits one final event. It does not provide incremental events, bidirectional audio, acknowledgements, or a resumable real-time session.
6. The application composition currently creates the AGLI lookup adapter in API dependencies and uses a module-level provider router. M15/M16 engines, policy, and device services should move behind explicit trusted application composition rather than add more module globals.
7. Identity and memory are account-scoped, but there is no complete device registry, per-device revocation model, or synchronization protocol.
8. The database implementation currently supports SQLite only. Multi-device synchronization and multi-process deployment must not be treated as solved by the existing persistence layer.
9. The repository has no Android or desktop application project.
10. There is no verified SIM-call audio integration, VoIP media integration, audio capture pipeline, local speech model runtime, or production deployment configuration.

## 3. Target architecture and ownership

### 3.1 Backend modules

Keep these as modular packages with explicit interfaces:

- `identity`: account authentication, device enrollment, device lifecycle, sessions, and revocation.
- `policy`: authorization, purpose-specific consent, data classification, retention, and capability decisions.
- `providers`: text, translation, ASR, TTS, and local-runtime adapters; provider profiles and privacy-aware routing.
- `agli`: language/dialect metadata, language detection, translation orchestration, speech pipeline, accessibility, and quality evaluation.
- `events`: versioned event envelope, streaming sessions, sequencing, cancellation, and reconnect semantics.
- `memory`: existing owner-controlled memory plus explicit sync eligibility and conflict policy.
- `devices`: registered devices, supported capabilities, platform permissions reported by clients, and device revocation.
- `sync`: versioned, authenticated, resumable synchronization protocol; no direct client access to database tables.
- `intelligence`: existing orchestration core coordinates these modules but does not own their provider-specific or OS-specific implementations.
- `tools`: existing risk, authorization, passkey, certification, and recovery lifecycle remains authoritative.

### 3.2 Composition

Create one trusted application composition root that builds repositories, policy services, provider registries, AGLI engines, event services, and device/sync services. Inject these dependencies into API routes and workers. Do not accept provider profiles, engine registrations, permission grants, device trust claims, or conformance evidence from ordinary request JSON.

Keep the current API endpoints backward-compatible while adding versioned contracts for the new capabilities. The central core should not import Android, desktop, SDK-specific, audio codec, or provider-specific implementation details.

### 3.3 Client architecture

Recommended initial client direction:

- **Android:** native Kotlin application. Android-specific microphone, audio focus, foreground service, notification, accessibility, and telephony/VoIP integrations remain in narrow platform adapters.
- **Desktop:** a Tauri-based shell with a web UI and constrained Rust/native capability bridge. OS file, microphone, audio-device, and accessibility access must be mediated by explicit permissions and a local capability gateway.
- **Shared contract:** OpenAPI-generated API types plus versioned JSON event schemas. Share behavior and data contracts, not OS permission logic or security authority.

This is a proposed stack decision, not a claim that either client exists. Before implementation, record an ADR confirming build tooling, supported desktop operating systems, signing/update strategy, and the user's target Android versions.

Clients are not trusted policy authorities. A client permission prompt is necessary for OS access but does not replace AIBrain account consent or action authorization.

## 4. M15 — Adaptive Global Language Intelligence

### M15.1 Language and capability contracts

Keep BCP 47 language tags and dialect metadata. Extend capability records so the system can distinguish at least:

- registered;
- implemented;
- available in this runtime/device;
- verified by a named evaluation suite and version;
- disabled or unavailable by policy.

A language/capability pair must not be advertised as available merely because a language is registered. Include provider/engine version, modality, supported direction pairs, locale/dialect coverage, execution location, and evaluation evidence in trusted engine metadata.

Initial capability IDs:

- `language_detection`
- `text_translation`
- `speech_recognition`
- `speech_synthesis`
- `streaming_translation`
- `live_communication_translation`

Do not silently equate language identification, translation, transliteration, and speech recognition.

### M15.2 Text language engine

Define provider-neutral request/result contracts for language detection and text translation. Requests carry source and target language tags (source may be auto-detected), text size limits, purpose/data classification, and optional user-approved context. Results carry detected language, confidence, translated text, engine identity/version, and bounded quality metadata.

Preserve source text separately from translated output. Do not write either into personal memory unless the user has explicitly enabled the applicable memory purpose.

### M15.3 Speech pipeline

Use a staged pipeline behind interfaces:

1. client capture adapter obtains audio only after OS permission and explicit in-product user action;
2. audio session policy checks purpose, participant notice/consent where applicable, data classification, duration, and size limits;
3. audio ingress validates codec, sample rate, channel count, frame size, timestamps, and session binding;
4. ASR adapter emits partial/final transcript segments with language, timestamps, and confidence;
5. translation adapter emits aligned translated segments;
6. optional TTS adapter emits synthesized audio through a separate output stream;
7. client renders captions/audio and exposes pause, stop, clear, and consent state.

Raw audio is ephemeral by default and must not be logged. Persistent recording is a separate feature requiring explicit consent, retention, deletion, export, and encryption policy. Transcript retention is also separate from audio retention. Provider adapters must not retain media outside their declared and approved contract.

### M15.4 Real-time event protocol

Use WebSocket (or another explicitly selected bidirectional transport) for live audio sessions; retain REST for session creation, policy checks, and lifecycle operations. SSE can remain useful for one-way text updates but is not the audio transport.

Every event uses a versioned envelope with:

- event ID and session ID;
- schema version and event type;
- monotonically increasing sequence number;
- timestamp and bounded correlation ID;
- payload with a strict size limit;
- explicit final/partial semantics where applicable.

Define handshake, capability negotiation, backpressure, bounded queues, acknowledgement, reconnect/resume, cancellation, timeout, and terminal error behavior. Never accept client-supplied user identity or consent state as authority; bind the live session to the authenticated account, enrolled device, and server-side policy decision.

### M15.5 Offline and hybrid execution

Define a local engine adapter using the same capability contracts as cloud providers. A local engine is available only after the model is installed, integrity-checked, licensed for the intended use, and successfully self-tested. Record model version, hash, supported languages, resource requirements, and execution location.

Routing must consider user policy, data classification, local/cloud allowance, language pair, capability, latency, cost, battery/resource budget, and residency. A cloud fallback that changes the privacy boundary requires an explicit policy decision; never silently upload audio because the local model is unavailable.

Do not bundle large model weights into the backend package. Model acquisition, signatures, storage, updates, rollback, and disk limits require a separate reviewed lifecycle.

### M15.6 Live communication and call boundaries

Separate three integration classes:

1. **VoIP integrations:** use an approved provider SDK/API only when it exposes media under a documented permission and participant-consent model.
2. **Desktop communication apps:** integrate only through documented APIs or a user-selected audio device/loopback route with explicit capture indication and stop controls.
3. **Cellular/SIM calls on Android:** ordinary applications cannot assume unrestricted access to both sides of cellular call audio. Investigate only supported Android telecom roles, carrier/OEM APIs, or user-mediated external audio routes. Do not promise direct SIM-call capture or bypass OS restrictions.

Call translation is not enabled until real-device tests prove the supported route, participant notice, audio routing, interruption behavior, and revocation. No silent call recording, hidden capture, or voice impersonation.

### M15.7 Evaluation and completion gate

Build a versioned multilingual test corpus with licensed/consented data, language/dialect coverage, accuracy/quality scoring, confidence calibration, latency, interruption, noise, clipping, and failure tests. Do not publish quality claims without reproducible measurements.

M15 is complete only when:
- at least one real, approved text translation engine is verified;
- speech recognition and synthesis work through real adapters on supported targets;
- streaming translation has measurable latency and robust cancellation/reconnect;
- offline capability is tested on declared hardware and languages;
- any claimed call workflow passes real-device/provider conformance;
- consent, retention, redaction, deletion, and provider-boundary tests pass;
- capability status reflects evidence rather than registration.

## 5. M16 — Universal Cross-Platform Personal Assistant

### M16.1 Device identity and sessions

Add a durable device registry separate from accounts and passkey credentials. A device record should include opaque device ID, owner ID, platform, app version, public-key/fingerprint reference, enrollment time, last-seen time, status, and revocation metadata. Avoid collecting unnecessary hardware identifiers.

Device enrollment requires an authenticated account and explicit user confirmation. Device authentication must bind a session to both account and enrolled device. Revocation must invalidate device sessions and sync credentials promptly. A device must not gain broader tool authority merely because it is enrolled.

### M16.2 API and capability negotiation

Expose authenticated endpoints for device enrollment, listing, status, capability declaration, and revocation. Client-declared capabilities are descriptive and must be verified or permission-checked at the point of use. Examples include microphone, notifications, accessibility, file access, and supported local inference.

Use versioned API schemas and compatibility rules. Clients must handle unsupported capabilities and server versions without silently changing security behavior.

### M16.3 Cross-device memory and synchronization

Define sync as an explicit protocol, not a database replication shortcut. It must support:

- per-account and per-device authorization;
- TLS transport and encrypted payload policy;
- opaque cursor/checkpoint and resumable batches;
- idempotent operation IDs;
- versioned records and schema migrations;
- deletion tombstones that propagate to replicas and derived caches;
- deterministic conflict detection and user-mediated resolution for personal facts;
- device-local-only records and explicit sync eligibility;
- audit events without leaking record contents.

Do not begin sensitive cross-device sync until the encryption/key-management ADR is approved. Define whether payloads are end-to-end encrypted, how device keys are enrolled/revoked/recovered, and what the server can decrypt. Do not describe ordinary TLS or server-side encryption as end-to-end encryption.

SQLite is currently the only database implementation. The first sync deployment must validate transaction boundaries, concurrent writers, backup/restore, and single-node constraints. Keep repositories abstracted so a future server database can be introduced without leaking SQL into API/client contracts.

### M16.4 Personal assistant surfaces

Android and desktop provide consistent access to:

- conversation and voice interface;
- explicit memory and Digital Twin review/correction/deletion;
- task planning and proposal review;
- authorized tool execution status and cancellation;
- language/translation sessions;
- connected integration status;
- privacy, permissions, devices, and session controls.

The client renders plans as proposals. It must not execute consequential actions directly or bypass the existing M9/M11 authorization, passkey, certification, and recovery lifecycle.

### M16.5 Offline-first behavior

Classify operations:

- safe local reads and local drafts may be available offline;
- syncable memory changes enter a bounded, encrypted, idempotent outbox;
- plans may be drafted offline but must be revalidated against live server authority before authorization;
- consequential actions and external dispatch are unavailable offline;
- unknown outcomes are reconciled, never blindly replayed.

Expose stale state and sync conflicts to the user. Device revocation and account logout must clear or cryptographically disable locally cached credentials and protected data according to the approved key lifecycle.

### M16.6 Desktop local capability gateway

Desktop file, application, shell, accessibility, and audio capabilities must be separate registered tools with least privilege, strict schemas, visible user consent, bounded execution, and audit. Do not give the model a general unrestricted shell or filesystem. Each local action must pass the same risk classification and authorization policy as backend tools, with a local execution boundary that binds owner, device, action digest, and approval.

### M16.7 M16 completion gate

M16 is complete only when:
- Android and desktop clients build, install, update, and pass supported-OS tests;
- account/device enrollment, session binding, and revocation are verified;
- user-approved memory sync is encrypted according to the approved threat model and handles conflict/deletion correctly;
- offline queue/recovery behavior is tested, including unknown outcomes;
- local device permissions and tool boundaries are enforced;
- cross-device workflows pass end-to-end tests without weakening existing backend security.

## 6. Shared security invariants

These requirements apply to both milestones:

1. Consent is purpose-specific, explicit, revocable, and checked server-side at use time.
2. OS permission does not imply AIBrain consent; AIBrain consent does not bypass OS permission.
3. No hidden audio capture, silent recording, or voice cloning/impersonation.
4. No raw audio, transcript, personal memory, or secrets in ordinary logs, traces, analytics, or provider metadata.
5. Cloud routing is prohibited when the active data policy allows local-only execution.
6. No client-supplied provider profile, trust evidence, authorization decision, or capability grant.
7. Device enrollment is not equivalent to tool authorization.
8. Existing owner scoping, passkey approval, tool certification, dispatch ledger, no-auto-retry, and unknown-outcome reconciliation remain mandatory.
9. Deletion and revocation propagate to active sessions, caches, replicas, and queued work.
10. Fail closed when consent, device trust, provider capability, model integrity, or policy state cannot be established.

## 7. Coordinated delivery sequence

Implement both milestones together in the following shared increments. Each increment must land behind tests and must not claim unavailable features.

| Increment | M15 deliverable | M16 deliverable | Shared dependency |
|---|---|---|---|
| A. Contracts and composition | Language/engine/capability contracts | Device and client API contracts | Trusted composition, policy, schemas |
| B. Identity and permissions | Audio-purpose consent contract | Device enrollment/revocation | Identity and policy |
| C. Text intelligence and clients | Detection/translation adapters | Android/desktop shells and API clients | Provider routing, OpenAPI |
| D. Streaming and speech | Audio session, ASR/TTS, event protocol | Voice UI and device transport | Event envelope, cancellation |
| E. Offline and sync | Local language runtime and policy routing | Local cache/outbox and sync | Key lifecycle, conflict model |
| F. Communication integrations | Approved VoIP and supported call paths | OS-level audio/telecom adapters | Real-device/provider permissions |
| G. Hardening and release | Quality/latency/privacy conformance | Device/security/release conformance | Observability, backups, recovery |

## 8. Required architecture decisions before sensitive implementation

Create reviewed ADRs for:

1. Android and desktop client technology, supported OS versions, signing, and update channel.
2. WebSocket protocol, event schema versioning, reconnect, and backpressure.
3. Audio codecs, frame limits, media transport, and ephemeral processing boundaries.
4. Provider selection and licensing for translation, ASR, and TTS.
5. Local model packaging, integrity verification, updates, resource budgets, and rollback.
6. Device enrollment and device-bound session credential lifecycle.
7. End-to-end encryption, key recovery, device revocation, and sync conflict semantics.
8. Supported cellular/VoIP integration paths for the exact target Android versions and providers.
9. Production database and deployment topology before multi-device sync is enabled.

## 9. Verification strategy

For every increment:

```bash
python -m compileall -q backend tests scripts
pytest -q <focused-tests>
pytest -q
python -m pip check
git diff --check
git status --short
```

Add contract tests, API authorization tests, provider conformance tests, property/fuzz tests for media framing and event parsing, concurrency/revocation tests, offline recovery tests, and device end-to-end tests. Use real devices and approved provider test accounts for claims involving microphone, VoIP, or cellular calls.

The M11–M14 baseline currently reported by the developer is 937 passing tests. Preserve it as the regression baseline; any intentional change to expected behavior must include updated tests and a documented reason.

## 10. Explicit non-goals for the first combined release

- No unrestricted access to cellular call audio.
- No automatic call recording or transcript retention.
- No model-generated authority or inferred consent.
- No general-purpose unrestricted local shell.
- No offline execution of consequential external actions.
- No automatic replay of uncertain external dispatch.
- No claim of end-to-end encryption before the key lifecycle is implemented and tested.
- No production cloud/local provider availability claim before provider-specific integration and conformance.
- No microservices solely to make the architecture appear distributed.
