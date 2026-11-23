from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state
from backend.app.persistence.validation import validate_personal_payload


router = APIRouter(prefix="/personal", tags=["personal"])


class MemoryCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    memory_type: str = Field(pattern=r"^(preference|goal|context|project)$")
    key: str = Field(min_length=1, max_length=200)
    value: object
    source: str = Field(min_length=1, max_length=100)
    confidence: float = Field(ge=0.0, le=1.0)
    expires_at: str | None = None


class MemoryUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: object
    confidence: float = Field(ge=0.0, le=1.0)


class ObservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=100)
    observation: object


class AdaptationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal: object


class AdaptationStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(pattern=r"^(approved|rejected|suspended|revoked)$")


@router.post("/memory")
async def create_memory(
    request: MemoryCreateRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        validate_personal_payload(request.value)
        return get_app_state().memory.create(
            user["id"],
            memory_type=request.memory_type,
            key=request.key,
            value=request.value,
            source=request.source,
            confidence=request.confidence,
            expires_at=request.expires_at,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_MEMORY", "message": "Invalid memory"},
        ) from None


@router.get("/memory")
async def list_memory(
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return list(get_app_state().memory.list(user["id"]))


@router.patch("/memory/{memory_id}")
async def update_memory(
    memory_id: str,
    request: MemoryUpdateRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        validate_personal_payload(request.value)
        return get_app_state().memory.update(
            user["id"],
            memory_id,
            value=request.value,
            confidence=request.confidence,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_PERSONAL_DATA", "message": "Invalid personal data"},
        ) from None
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "MEMORY_NOT_FOUND", "message": "Memory not found"},
        ) from None


@router.delete("/memory/{memory_id}")
async def delete_memory(
    memory_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    deleted = get_app_state().memory.delete(user["id"], memory_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail={"code": "MEMORY_NOT_FOUND", "message": "Memory not found"},
        )
    return {"deleted": True}


@router.post("/memory/export")
async def export_memory(
    user: dict = Depends(get_current_user),
) -> dict:
    return get_app_state().memory.export(user["id"])


@router.get("/learning/observations")
async def list_observations(
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return list(
        get_app_state().learning.list_observations(user["id"])
    )


@router.get("/learning/observations/{observation_id}")
async def get_observation(
    observation_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().learning.get_observation(
            user["id"],
            observation_id,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "OBSERVATION_NOT_FOUND",
                "message": "Observation not found",
            },
        ) from None


@router.post("/learning/observations")
async def record_observation(
    request: ObservationRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        validate_personal_payload(request.observation)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_PERSONAL_DATA", "message": "Invalid personal data"},
        ) from None
    return get_app_state().learning.record_observation(
        user["id"],
        source=request.source,
        observation=request.observation,
    )


@router.post("/learning/adaptations")
async def propose_adaptation(
    request: AdaptationRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        validate_personal_payload(request.proposal)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_PERSONAL_DATA", "message": "Invalid personal data"},
        ) from None
    return get_app_state().learning.propose_adaptation(
        user["id"],
        proposal=request.proposal,
    )


@router.get("/learning/adaptations")
async def list_adaptations(
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return list(
        get_app_state().learning.list_adaptations(user["id"])
    )


@router.get("/learning/adaptations/{adaptation_id}")
async def get_adaptation(
    adaptation_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().learning.get_adaptation(
            user["id"],
            adaptation_id,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ADAPTATION_NOT_FOUND",
                "message": "Adaptation not found",
            },
        ) from None


@router.patch("/learning/adaptations/{adaptation_id}")
async def update_adaptation(
    adaptation_id: str,
    request: AdaptationStatusRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().learning.update_adaptation(
            user["id"],
            adaptation_id,
            status=request.status,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ADAPTATION_NOT_FOUND",
                "message": "Adaptation not found",
            },
        ) from None
