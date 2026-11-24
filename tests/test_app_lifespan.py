import pytest

from backend.app import main as main_module


class FakeAppState:
    tool_requests = object()
    memory = object()
    integration_connections = object()
    integration_orchestrator = object()


def install_lifecycle_fakes(monkeypatch, *, start_error=None, stop_error=None):
    events = []
    state = FakeAppState()

    class FakeRecoveryWorker:
        def __init__(self, repository, *, interval_seconds, stale_after_seconds):
            assert repository is state.tool_requests
            events.append(("construct", interval_seconds, stale_after_seconds))

        async def start(self):
            events.append("start")
            if start_error is not None:
                raise start_error

        async def stop(self):
            events.append("stop")
            if stop_error is not None:
                raise stop_error

    class FakeMemoryRetentionWorker:
        def __init__(self, repository, *, interval_seconds):
            assert repository is state.memory
            events.append(("construct-memory", interval_seconds))

        async def start(self):
            events.append("memory-start")

        async def stop(self):
            events.append("memory-stop")

    class FakeIntegrationExpiryWorker:
        def __init__(self, repository, *, interval_seconds):
            assert repository is state.integration_connections
            events.append(("construct-integration-expiry", interval_seconds))

        async def start(self):
            events.append("integration-expiry-start")

        async def stop(self):
            events.append("integration-expiry-stop")

    monkeypatch.setattr(main_module, "get_app_state", lambda settings: state)
    monkeypatch.setattr(
        main_module,
        "ToolExecutionRecoveryWorker",
        FakeRecoveryWorker,
    )
    monkeypatch.setattr(
        main_module,
        "MemoryRetentionWorker",
        FakeMemoryRetentionWorker,
    )
    monkeypatch.setattr(
        main_module,
        "IntegrationConnectionExpiryWorker",
        FakeIntegrationExpiryWorker,
    )

    class FakeIntegrationDispatchRecoveryWorker:
        def __init__(self, orchestrator, *, interval_seconds, stale_after_seconds):
            assert orchestrator is state.integration_orchestrator
            events.append(("construct-dispatch-recovery", interval_seconds, stale_after_seconds))

        async def start(self):
            events.append("dispatch-recovery-start")

        async def stop(self):
            events.append("dispatch-recovery-stop")

    monkeypatch.setattr(
        main_module,
        "IntegrationDispatchRecoveryWorker",
        FakeIntegrationDispatchRecoveryWorker,
    )
    monkeypatch.setattr(
        main_module,
        "reset_app_state",
        lambda: events.append("reset"),
    )
    return events


@pytest.mark.asyncio
async def test_application_lifespan_starts_and_stops_recovery_worker(monkeypatch):
    events = install_lifecycle_fakes(monkeypatch)

    async with main_module.lifespan(main_module.app):
        assert events == [
            (
                "construct",
                main_module.settings.tool_execution_recovery_interval_seconds,
                main_module.settings.tool_execution_stale_after_seconds,
            ),
            ("construct-memory", main_module.settings.memory_retention_interval_seconds),
            ("construct-integration-expiry", main_module.settings.integration_expiry_interval_seconds),
            (
                "construct-dispatch-recovery",
                main_module.settings.integration_dispatch_recovery_interval_seconds,
                main_module.settings.integration_dispatch_stale_after_seconds,
            ),
            "start",
            "memory-start",
            "integration-expiry-start",
            "dispatch-recovery-start",
        ]

    assert events[-5:] == [
        "dispatch-recovery-stop", "integration-expiry-stop",
        "memory-stop", "stop", "reset",
    ]


@pytest.mark.asyncio
async def test_application_lifespan_resets_state_if_worker_start_fails(monkeypatch):
    startup_error = RuntimeError("worker startup failed")
    events = install_lifecycle_fakes(monkeypatch, start_error=startup_error)

    with pytest.raises(RuntimeError, match="worker startup failed"):
        async with main_module.lifespan(main_module.app):
            pytest.fail("lifespan yielded after worker startup failed")

    assert events[-2:] == ["stop", "reset"]


@pytest.mark.asyncio
async def test_application_lifespan_resets_state_if_worker_stop_fails(monkeypatch):
    stop_error = RuntimeError("worker shutdown failed")
    events = install_lifecycle_fakes(monkeypatch, stop_error=stop_error)

    with pytest.raises(RuntimeError, match="worker shutdown failed"):
        async with main_module.lifespan(main_module.app):
            pass

    assert events[-2:] == ["stop", "reset"]


@pytest.mark.asyncio
async def test_application_lifespan_does_not_reset_before_worker_stops(monkeypatch):
    events = install_lifecycle_fakes(monkeypatch)

    async with main_module.lifespan(main_module.app):
        assert "reset" not in events

    assert (
        events.index("integration-expiry-stop")
        < events.index("memory-stop")
        < events.index("stop")
        < events.index("reset")
    )
