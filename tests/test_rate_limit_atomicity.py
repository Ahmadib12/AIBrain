from concurrent.futures import ThreadPoolExecutor
import threading

from backend.app.auth.rate_limit import LoginRateLimiter


def test_concurrent_attempts_cannot_exceed_rate_limit():
    limit = 7
    workers = 32
    limiter = LoginRateLimiter(limit=limit, window_seconds=60)
    barrier = threading.Barrier(workers)

    def attempt():
        barrier.wait()
        return limiter.check_and_record("same-client")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda _: attempt(), range(workers)))

    assert sum(results) == limit
    assert limiter.is_limited("same-client") is True


def test_atomic_attempts_allow_requests_again_after_reset():
    limiter = LoginRateLimiter(limit=2, window_seconds=60)

    assert limiter.check_and_record("user") is True
    assert limiter.check_and_record("user") is True
    assert limiter.check_and_record("user") is False

    limiter.reset("user")

    assert limiter.check_and_record("user") is True
