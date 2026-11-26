"""Opt-in integration test against a dedicated Redis test instance."""
import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from redis import Redis

from backend.app.persistence.security_recovery_abuse import RedisSecurityRecoveryAbuseMonitor


REDIS_TEST_URL = os.getenv("AIBRAIN_SECURITY_RECOVERY_ABUSE_REDIS_TEST_URL")
pytestmark = pytest.mark.skipif(
    not REDIS_TEST_URL,
    reason="set AIBRAIN_SECURITY_RECOVERY_ABUSE_REDIS_TEST_URL for a dedicated Redis test instance",
)


def test_real_redis_coordinates_recovery_limits_across_independent_clients():
    prefix = f"aibrain:recovery-abuse-integration:{uuid4().hex}"
    first_client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)
    second_client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)
    monitors = [
        RedisSecurityRecoveryAbuseMonitor(
            first_client,
            hmac_key="integration-test-secret-key-with-at-least-32-bytes",
            key_prefix=prefix,
        ),
        RedisSecurityRecoveryAbuseMonitor(
            second_client,
            hmac_key="integration-test-secret-key-with-at-least-32-bytes",
            key_prefix=prefix,
        ),
    ]
    try:
        first_client.ping()
        with ThreadPoolExecutor(max_workers=10) as pool:
            allowed = list(pool.map(
                lambda index: monitors[index % 2].check_and_record(
                    "redis-integration-owner@example.com",
                    limit=5,
                    window_seconds=300,
                ),
                range(25),
            ))
        assert sum(allowed) == 5
        assert monitors[0].metrics()["attempts"] == 25
        assert monitors[1].metrics()["blocked_attempts"] == 20
    finally:
        keys = list(first_client.scan_iter(match=f"{prefix}:*"))
        if keys:
            first_client.delete(*keys)
        first_client.close()
        second_client.close()
