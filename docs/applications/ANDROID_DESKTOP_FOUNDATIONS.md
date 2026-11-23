# Android and Desktop Application Foundations

There is no Android or desktop application project in the current repository.

## Shared backend contract

Future clients should use:

- `/api/v1/auth/*` for registration, login, session, and account operations.
- `/api/v1/personal/*` for memory and learning controls.
- `/api/v1/tools` for tool discovery.
- `/api/v1/intelligence/process` for bounded request/response intelligence.
- `/api/v1/intelligence/process/stream` for the current SSE-style response foundation.

## Required client boundaries

Android and desktop clients must:

- use secure platform credential storage;
- never store bearer credentials in logs or unencrypted application state;
- present consent and confirmation for consequential actions;
- keep authorization decisions in the backend;
- support session revocation;
- use the shared API schemas without duplicating provider or memory policy;
- disclose whether processing is local or cloud-backed.

## Explicit limitations

This repository has not tested:

- Android device behavior;
- desktop native runtimes;
- microphone or voice capture;
- accessibility APIs;
- ordinary SIM/cellular call capture;
- VoIP application integration.
