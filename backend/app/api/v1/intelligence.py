import asyncio
import logging

from fastapi import APIRouter, Depends
from backend.app.concurrency import require_ai_capacity
from fastapi.responses import JSONResponse, StreamingResponse

from backend.app.api.v1.dependencies import get_intelligence_core
from backend.app.intelligence.core import (
    CentralIntelligenceCore,
    OrchestrationCore,
)
from backend.app.intelligence.schemas import (
    IntelligenceRequest,
    IntelligenceResponse,
    ResponseStatus,
    TaskType,
)
from backend.app.intelligence.trace import (
    DecisionReasonCode,
    DecisionTraceBuilder,
)


router = APIRouter(prefix="/intelligence", tags=["intelligence"])


def _response_status_code(response: IntelligenceResponse) -> int:
    if response.status == ResponseStatus.UNSUPPORTED:
        return 400
    if response.status != ResponseStatus.ERROR:
        return 200
    return {
        "INVALID_REQUEST": 400,
        "LANGUAGE_NOT_FOUND": 404,
        "INVALID_PROVIDER_REQUEST": 400,
        "CAPABILITY_UNAVAILABLE": 503,
        "ADAPTER_UNAVAILABLE": 503,
        "REQUEST_TIMEOUT": 504,
        "PROVIDER_TIMEOUT": 504,
        "ADAPTER_TIMEOUT": 504,
        "ADAPTER_FAILURE": 502,
        "PROVIDER_FAILURE": 502,
        "ALL_PROVIDERS_FAILED": 503,
        "INVALID_ADAPTER_RESULT": 502,
    }.get(response.error_code, 500)


@router.post(
    "/process",
    response_model=IntelligenceResponse,
    responses={
        400: {"model": IntelligenceResponse},
        404: {"model": IntelligenceResponse},
        502: {"model": IntelligenceResponse},
        503: {"model": IntelligenceResponse},
        504: {"model": IntelligenceResponse},
        500: {"model": IntelligenceResponse},
    },
)
async def process_intelligence(
    request: IntelligenceRequest,
    core: CentralIntelligenceCore = Depends(get_intelligence_core),
    _capacity: None = Depends(require_ai_capacity, scope='request'),
) -> IntelligenceResponse | JSONResponse:
    try:
        response = await core.process(request)
    except asyncio.CancelledError:
        raise
    except Exception:
        logging.getLogger("aibrain.intelligence").error(
            "Unexpected intelligence core failure"
        )
        response = IntelligenceResponse(
            task_type=TaskType.UNSUPPORTED,
            status=ResponseStatus.ERROR,
            error_code="INTELLIGENCE_FAILURE",
            warnings=("The request could not be processed",),
        )
        try:
            trace = DecisionTraceBuilder()
            trace.record_decision_reason(
                DecisionReasonCode.CORE_EXECUTION_FAILED
            )
            decision_trace = trace.build(
                request_id=response.request_id,
                response_status=response.status.value,
                error_code=response.error_code,
            )
            response = response.model_copy(
                update={"decision_trace": decision_trace}
            )
        except Exception:
            logging.getLogger("aibrain.intelligence").warning(
                "Decision trace recording failed"
            )

    status_code = _response_status_code(response)
    if status_code == 200:
        return response
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode="json"),
    )


@router.post("/process/stream")
async def process_intelligence_stream(
    request: IntelligenceRequest,
    core: CentralIntelligenceCore = Depends(get_intelligence_core),
    _capacity: None = Depends(require_ai_capacity, scope='request'),
):
    async def event_stream():
        try:
            response = await core.process(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            logging.getLogger("aibrain.intelligence").warning(
                "Stream intelligence core failure"
            )
            response = IntelligenceResponse(
                task_type=TaskType.UNSUPPORTED,
                status=ResponseStatus.ERROR,
                error_code="INTELLIGENCE_FAILURE",
                warnings=("The request could not be processed",),
            )
        yield (
            "data: "
            + response.model_dump_json()
            + "\n\n"
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
    )
