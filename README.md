# AIBrain

AIBrain is a foundation for a universal, adaptive, multi-model AI assistant. This repository currently implements the backend and the initial Global Language Intelligence (AGLI) foundation.

## Requirements

- Python 3.11 or newer
- A virtual environment

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

## Run the backend

```bash
uvicorn backend.app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`. Interactive documentation is available at:

- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI: `http://127.0.0.1:8000/openapi.json`

## API endpoints

- `GET /health` — liveness health check
- `GET /api/v1/health` — versioned health check
- `GET /api/v1/agli/languages` — list registered languages
- `GET /api/v1/agli/languages/{code}` — look up a language
- `GET /api/v1/providers` — list registered providers
- `GET /api/v1/providers/status` — provider health monitoring status
- `POST /api/v1/providers/health/{provider_id}` — run a provider health check
- `POST /api/v1/providers/chat` — route a test chat request

## Run tests

```bash
pytest
```

## Implemented in this milestone

- FastAPI application entry point
- Environment-based configuration
- Structured JSON logging
- Standard application error responses
- Versioned API routing
- Health endpoints
- AGLI language and dialect metadata schemas
- In-memory language registry
- Language lookup and validation
- Explicit capability status tracking
- pytest application and registry tests
- Provider-independent interfaces and schemas
- In-memory provider registry
- Priority-based model router
- Determinable mock AI provider
- Bounded fallback and retry handling
- Provider health monitoring
- Environment configuration for providers, priorities, timeout, retries, fallback, and mock behavior

## Provider configuration

Provider behavior can be configured through environment variables:

- `AIBRAIN_MOCK_PROVIDER_ENABLED` — enable or disable the mock provider
- `AIBRAIN_PROVIDER_PRIORITIES` — comma-separated provider priority values, for example `mock:100`
- `AIBRAIN_PROVIDER_TIMEOUT_SECONDS` — provider request timeout
- `AIBRAIN_PROVIDER_HEALTH_CHECK_TIMEOUT_SECONDS` — provider health-check timeout
- `AIBRAIN_PROVIDER_MAX_ATTEMPTS` — bounded attempts per provider
- `AIBRAIN_FALLBACK_ENABLED` — enable or disable fallback routing
- `AIBRAIN_MOCK_PROVIDER_SIMULATE_FAILURE` — make the mock provider fail predictably
- `AIBRAIN_DATABASE_URL` — SQLite database URL, default `sqlite:///:memory:`
- `AIBRAIN_TOOL_EXECUTION_RECOVERY_INTERVAL_SECONDS` — recovery worker polling interval, default `60`
- `AIBRAIN_TOOL_EXECUTION_STALE_AFTER_SECONDS` — age after which a claimed execution is marked `outcome_unknown`, default `300`

The recovery worker starts with the FastAPI application and stops during shutdown. It only marks stale attempts as `outcome_unknown`; it never retries or re-dispatches a tool. An uncertain external outcome must be reconciled explicitly.
- `AIBRAIN_SESSION_TTL_SECONDS` — bearer-session lifetime in seconds
- `AIBRAIN_LOGIN_RATE_LIMIT_ATTEMPTS` — process-local login failure limit
- `AIBRAIN_LOGIN_RATE_LIMIT_WINDOW_SECONDS` — process-local login limit window

The mock provider is intentionally deterministic and does not call external services.

## Capability status model

AGLI capability profiles use four states:

- `registered`: metadata exists in the registry
- `implemented`: code implements the capability
- `available`: an implemented capability is usable in the current runtime
- `verified`: availability has been evaluated with passing tests or benchmarks

Registering a language does not claim that translation, speech recognition, or speech synthesis is implemented.

## Current limitations

- No real external AI provider integration
- No real provider API credentials or paid-service calls
- No language-detection model
- No speech recognition or synthesis
- No live-call or mobile functionality
- No production deployment configuration
- No Android or desktop application project
- No real local-model runtime
- No real tool implementations with consequential side effects
- No complete distributed synchronization system

## Implemented foundations beyond the original milestones

- SQLite migrations and versioned persistence
- PBKDF2 password storage and bearer sessions
- Tenant-isolated personal-memory repositories and APIs
- Explicit behavioral-learning observation and adaptation approval
- Safe tool discovery and a read-only echo tool gateway
- Local-provider and advanced-AGLI interfaces
- Typed multimodal and stream-event contracts
- SSE-style intelligence response endpoint
- Bounded health-check timeout and per-provider health-check locking
