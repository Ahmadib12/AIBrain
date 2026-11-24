import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.persistence.integration_dispatch_recovery import (
    IntegrationDispatchRecoveryWorker,
)


class FakeOrchestrator:
    def __init__(self, recovered=0):
        self.recovered = recovered
        self.cutoffs = []

    def recover_stale_dispatches(self, *, stale_before):
        self.cutoffs.append(stale_before)
        return self.recovered


def test_dispatch_recovery_worker_uses_configured_staleness_cutoff():
    orchestrator = FakeOrchestrator(recovered=3)
    worker = IntegrationDispatchRecoveryWorker(
        orchestrator, interval_seconds=1, stale_after_seconds=120
    )

    recovered = asyncio.run(worker.run_once())

    assert recovered == 3
    assert len(orchestrator.cutoffs) == 1
    cutoff = datetime.fromisoformat(orchestrator.cutoffs[0])
    age = datetime.now(timezone.utc) - cutoff
    assert timedelta(seconds=119) <= age <= timedelta(seconds=121)


@pytest.mark.parametrize(
    "interval,stale_after",
    [(0, 1), (1, 0), (-1, 5), (5, -1)],
)
def test_dispatch_recovery_worker_rejects_invalid_intervals(interval, stale_after):
    with pytest.raises(ValueError, match="must be positive"):
        IntegrationDispatchRecoveryWorker(
            FakeOrchestrator(),
            interval_seconds=interval,
            stale_after_seconds=stale_after,
        )
