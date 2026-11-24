import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException
from backend.app.concurrency import require_ai_capacity
from fastapi.responses import JSONResponse, StreamingResponse

from backend.app.api.v1.dependencies import get_intelligence_core
from backend.app.api.v1.auth import get_optional_current_user
from backend.app.app_state import get_app_state
from backend.app.intelligence.memory_context import MemoryContextAssembler
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




def _requested_memory_context(request: IntelligenceRequest, user: dict | None) -> str | None:
    if not request.use_memory:
        return None
    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "Sign in to use your saved memory",
            },
        )
    latest_user_message = next(
        (
            message.content
            for message in reversed(request.messages)
            if message.role.value == "user"
        ),
        None,
    )
    if latest_user_message is None:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "MEMORY_QUERY_REQUIRED",
                "message": "A user message is required for memory retrieval",
            },
        )
    try:
        result = MemoryContextAssembler().assemble(
            get_app_state().memory,
            user_id=user["id"],
            query=latest_user_message,
            limit=5,
        )
        return result.to_provider_context()
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "MEMORY_CONSENT_REQUIRED",
                "message": "Active memory consent is required to use saved memory",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_MEMORY_QUERY",
                "message": "The request cannot be used for memory retrieval",
            },
        ) from None


async def _run_core(
    core: CentralIntelligenceCore,
    request: IntelligenceRequest,
    memory_context: str | None,
) -> IntelligenceResponse:
    if memory_context is None:
        return await core.process(request)
    if not isinstance(core, OrchestrationCore):
        raise HTTPException(
            status_code=503,
            detail={
                "code": "MEMORY_CONTEXT_UNAVAILABLE",
                "message": "This intelligence core does not support approved memory context",
            },
        )
    return await core.process(request, memory_context=memory_context)


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
    user: dict | None = Depends(get_optional_current_user),
) -> IntelligenceResponse | JSONResponse:
    memory_context = _requested_memory_context(request, user)
    try:
        response = await _run_core(core, request, memory_context)
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
    user: dict | None = Depends(get_optional_current_user),
):
    memory_context = _requested_memory_context(request, user)

    async def event_stream():
        try:
            response = await _run_core(core, request, memory_context)
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
