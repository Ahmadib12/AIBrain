import pytest

from backend.app.intelligence.adapters import AdapterResult, CapabilityAdapter
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.core import OrchestrationCore
from backend.app.intelligence.schemas import IntelligenceRequest


class RecordingAdapter(CapabilityAdapter):
    def __init__(self) -> None:
        self.calls = 0

    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        self.calls += 1
        return AdapterResult(content="A safe test response")


@pytest.mark.asyncio
async def test_core_includes_plan_for_successful_intelligence_request() -> None:
    adapter = RecordingAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Compare two devices"}]
    )

    response = await core.process(request)

    assert response.status.value == "completed"
    assert response.content == "A safe test response"
    assert response.planning is not None
    assert response.planning["intent"]["kind"] == "analyze"
    assert response.planning["assessment"]["plan_valid"] is True
    assert response.planning["assessment"]["missing_capabilities"] == []
    assert response.planning["assessment"]["execution_permitted"] is False
    assert adapter.calls == 1


@pytest.mark.asyncio
async def test_core_exposes_unsupported_control_plan_without_executing_adapter() -> None:
    adapter = RecordingAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Send an email to my manager"}]
    )

    response = await core.process(request)

    assert response.status.value == "unsupported"
    assert response.planning is not None
    assert response.planning["intent"]["kind"] == "control"
    assert response.planning["assessment"]["requires_authorization"] is True
    assert response.planning["assessment"]["execution_permitted"] is False
    assert response.planning["plan"]["tasks"][0]["kind"] == "request_input"
    assert adapter.calls == 0


@pytest.mark.asyncio
async def test_planning_failure_does_not_bypass_existing_core_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = RecordingAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})

    def fail_plan(*args, **kwargs):
        raise RuntimeError("PRIVATE_PLANNING_FAILURE_DETAIL")

    monkeypatch.setattr(core.planning_engine, "plan", fail_plan)
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Explain DNS"}]
    )

    response = await core.process(request)

    assert response.status.value == "completed"
    assert response.planning is None
    assert adapter.calls == 1

class ProviderFailureAdapter(CapabilityAdapter):
    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        from backend.app.intelligence.adapters import ProviderRoutingAdapterError

        raise ProviderRoutingAdapterError("PROVIDER_FAILURE")


@pytest.mark.asyncio
async def test_error_response_does_not_expose_user_text_through_planning() -> None:
    core = OrchestrationCore(
        adapters={"text_generation": ProviderFailureAdapter()}
    )
    request = IntelligenceRequest(
        messages=[{
            "role": "user",
            "content": "Analyze this private phrase: ORCHID-PRIVATE-4821",
        }]
    )

    response = await core.process(request)

    assert response.status.value == "error"
    assert response.error_code == "PROVIDER_FAILURE"
    assert response.planning is None
    assert "ORCHID-PRIVATE-4821" not in str(response.model_dump())




@pytest.mark.asyncio
async def test_core_passes_prior_turns_to_context_aware_planning() -> None:
    adapter = RecordingAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})
    request = IntelligenceRequest(
        messages=[
            {"role": "user", "content": "Explain how DNS works"},
            {"role": "assistant", "content": "DNS translates domain names into IP addresses."},
            {"role": "user", "content": "Make it shorter"},
        ]
    )

    response = await core.process(request)

    assert response.status.value == "completed"
    assert response.planning is not None
    assert response.planning["intent"]["kind"] == "transform"
    assert response.planning["intent"]["context_used"] is True
    assert response.planning["assessment"]["requires_clarification"] is False
    assert response.planning["assessment"]["execution_permitted"] is False
    assert adapter.calls == 1


@pytest.mark.asyncio
async def test_core_requests_clarification_for_follow_up_without_history() -> None:
    adapter = RecordingAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Make it shorter"}]
    )

    response = await core.process(request)

    assert response.status.value == "completed"
    assert response.planning is not None
    assert response.planning["assessment"]["requires_clarification"] is True
    assert response.planning["plan"]["tasks"][0]["task_id"] == "clarify-context"
    assert response.planning["assessment"]["execution_permitted"] is False
    assert adapter.calls == 1
