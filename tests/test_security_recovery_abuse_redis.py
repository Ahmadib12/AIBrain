from concurrent.futures import ThreadPoolExecutor

import fakeredis
import pytest

from backend.app.config import Settings
from backend.app.persistence.security_recovery_abuse import (
    RecoveryAbuseUnavailable,
    RedisSecurityRecoveryAbuseMonitor,
)


def _shared_monitors():
    server = fakeredis.FakeServer()
    clients = [
        fakeredis.FakeRedis(server=server, decode_responses=True),
        fakeredis.FakeRedis(server=server, decode_responses=True),
    ]
    return clients, [
        RedisSecurityRecoveryAbuseMonitor(
            client,
            hmac_key="test-only-hmac-key-with-at-least-32-bytes",
        )
        for client in clients
    ]


def test_redis_recovery_abuse_limit_is_atomic_across_monitor_instances():
    _clients, monitors = _shared_monitors()

    def attempt(index):
        return monitors[index % 2].check_and_record(
            "shared-owner@example.com",
            source_ip="203.0.113.42",
            limit=5,
            ip_limit=100,
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(attempt, range(40)))

    assert sum(results) == 5
    assert monitors[0].metrics() == {
        "attempts": 40,
        "blocked_attempts": 35,
        "active_scopes": 2,
    }


def test_redis_recovery_abuse_enforces_shared_ip_across_different_accounts():
    _clients, monitors = _shared_monitors()
    results = [
        monitors[index % 2].check_and_record(
            f"owner-{index}@example.com",
            source_ip="198.51.100.19",
            limit=100,
            ip_limit=3,
        )
        for index in range(8)
    ]
    assert sum(results) == 3
    assert monitors[0].metrics()["blocked_attempts"] == 5


def test_redis_recovery_abuse_keys_do_not_expose_email_or_ip():
    clients, monitors = _shared_monitors()
    monitors[0].check_and_record(
        "private-owner@example.com",
        source_ip="192.0.2.77",
    )
    keys = [key.decode() if isinstance(key, bytes) else key for key in clients[0].keys("*")]
    assert keys
    assert all("private-owner" not in key for key in keys)
    assert all("192.0.2.77" not in key for key in keys)


def test_redis_recovery_abuse_fails_closed_when_shared_store_is_unavailable():
    class UnavailableRedis:
        def time(self):
            return (1_800_000_000, 0)

        def eval(self, *_args):
            raise OSError("connection unavailable")

    monitor = RedisSecurityRecoveryAbuseMonitor(
        UnavailableRedis(),
        hmac_key="test-only-hmac-key-with-at-least-32-bytes",
    )
    with pytest.raises(RecoveryAbuseUnavailable):
        monitor.check_and_record("owner@example.com")


def test_redis_recovery_abuse_settings_require_shared_url_and_stable_hmac_key():
    with pytest.raises(ValueError, match="Redis recovery abuse protection requires"):
        Settings(security_recovery_abuse_backend="redis")

    settings = Settings(
        security_recovery_abuse_backend="redis",
        security_recovery_abuse_redis_url="rediss://redis.example.test:6380/2",
        security_recovery_abuse_hmac_key="stable-deployment-secret-key-at-least-32",
    )
    assert settings.security_recovery_abuse_backend == "redis"

    with pytest.raises(ValueError, match="HMAC key must contain at least 32 bytes"):
        Settings(
            security_recovery_abuse_backend="redis",
            security_recovery_abuse_redis_url="redis://localhost:6379/0",
            security_recovery_abuse_hmac_key="short",
        )

    with pytest.raises(ValueError, match="Redis key prefix is invalid"):
        Settings(security_recovery_abuse_redis_key_prefix="unsafe:{tag}")


def test_recovery_api_returns_503_instead_of_bypassing_shared_limits():
    from uuid import uuid4

    from fastapi.testclient import TestClient

    from backend.app.app_state import get_app_state
    from backend.app.main import app

    class UnavailableMonitor:
        def check_and_record(self, *_args, **_kwargs):
            raise RecoveryAbuseUnavailable("Redis unavailable")

    with TestClient(app) as client:
        state = get_app_state()
        state.security_recovery_abuse = UnavailableMonitor()
        response = client.post(
            f"/api/v1/devices/{uuid4()}/recovery/challenge",
            json={
                "email": "owner@example.com",
                "recovery_code": "R" * 32,
                "new_public_key_b64": "A" * 44,
            },
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DEVICE_RECOVERY_PROTECTION_UNAVAILABLE"
    assert response.json()["error"]["message"] == "Device recovery is temporarily unavailable"
