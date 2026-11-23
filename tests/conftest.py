import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.api.v1.providers import provider_router


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def operator_headers(monkeypatch) -> dict[str, str]:
    token = "test-provider-operator-token-32chars"
    monkeypatch.setenv("AIBRAIN_PROVIDER_OPERATOR_TOKEN", token)
    return {"X-AIBrain-Operator-Token": token}


@pytest.fixture(autouse=True)
def reset_provider_health_state() -> None:
    provider_router.health_monitor._statuses.clear()
    provider_router.health_monitor._health_check_locks.clear()
    yield
    provider_router.health_monitor._statuses.clear()
    provider_router.health_monitor._health_check_locks.clear()

@pytest.fixture(autouse=True)
def reset_registration_rate_limiter(monkeypatch):
    from backend.app.api.v1 import auth as auth_api
    from backend.app.auth.rate_limit import LoginRateLimiter

    original = auth_api._registration_rate_limiter
    auth_api._registration_rate_limiter = LoginRateLimiter(
        original.limit,
        original.window_seconds,
        original.max_entries,
    )
    yield
    auth_api._registration_rate_limiter = original
