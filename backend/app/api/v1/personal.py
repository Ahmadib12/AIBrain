import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state
from backend.app.intelligence.memory_context import MemoryContextAssembler
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
    key: str | None = Field(default=None, min_length=1, max_length=200)
    memory_type: str | None = Field(
        default=None,
        pattern=r"^(preference|goal|context|project)$",
    )


class MemoryConsentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retention_days: int | None = Field(default=365, ge=1, le=3650)


class MemoryRetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retention_days: int | None = Field(ge=1, le=3650)


class MemorySearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=5, ge=1, le=10)


class MemoryContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=5, ge=1, le=5)


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


@router.get("/memory/consent")
async def get_memory_consent(
    user: dict = Depends(get_current_user),
) -> dict:
    return get_app_state().memory.consent_status(user["id"])


@router.post("/memory/consent")
async def grant_memory_consent(
    request: MemoryConsentRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        consent = get_app_state().memory.grant_consent(
            user["id"],
            retention_days=request.retention_days,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_MEMORY_POLICY", "message": "Invalid memory policy"},
        ) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=401,
            detail={"code": "UNAUTHORIZED", "message": "The account is not active"},
        ) from None
    return {
        "consent": consent,
        "notice": (
            "Personal memory is enabled only for this account. You can revoke "
            "consent, export, change retention, or delete stored memories at any time."
        ),
    }


@router.patch("/memory/consent/retention")
async def update_memory_retention(
    request: MemoryRetentionRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().memory.set_retention_policy(
            user["id"],
            retention_days=request.retention_days,
        )
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "MEMORY_CONSENT_REQUIRED",
                "message": "Grant memory consent before changing its retention policy",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_MEMORY_POLICY", "message": "Invalid memory policy"},
        ) from None


@router.delete("/memory/consent")
async def revoke_memory_consent(
    purge_existing: bool = Query(default=False),
    user: dict = Depends(get_current_user),
) -> dict:
    # Revocation takes effect immediately. Existing records are locked from
    # retrieval; purge_existing=true additionally erases those records now.
    return get_app_state().memory.revoke_consent(
        user["id"],
        purge_existing=purge_existing,
    )


@router.post("/memory")
async def create_memory(
    request: MemoryCreateRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        validate_personal_payload(request.key)
        validate_personal_payload(request.source)
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
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "MEMORY_CONSENT_REQUIRED",
                "message": "Explicit memory consent is required before saving memories",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_MEMORY", "message": "Invalid memory"},
        ) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=401,
            detail={"code": "UNAUTHORIZED", "message": "The account is not active"},
        ) from None


@router.get("/memory")
async def list_memory(
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return list(get_app_state().memory.list(user["id"]))


@router.get("/memory/{memory_id}")
async def get_memory(
    memory_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().memory.get(user["id"], memory_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "MEMORY_NOT_FOUND", "message": "Memory not found"},
        ) from None


@router.post("/memory/search")
async def search_memory(
    request: MemorySearchRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    state = get_app_state()
    try:
        assembled = MemoryContextAssembler().assemble(
            state.memory,
            user_id=user["id"],
            query=request.query,
            limit=request.limit,
        )
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "MEMORY_CONSENT_REQUIRED",
                "message": "Active memory consent is required for retrieval",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_MEMORY_QUERY", "message": "Invalid memory query"},
        ) from None
    return {
        "query": assembled.query,
        "matches": [
            item.model_dump(mode="json")
            for item in assembled.memories
        ],
        "truncated": assembled.truncated,
    }


@router.post("/memory/context")
async def assemble_memory_context(
    request: MemoryContextRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        result = MemoryContextAssembler().assemble(
            get_app_state().memory,
            user_id=user["id"],
            query=request.query,
            limit=request.limit,
        )
        return result.model_dump(mode="json")
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "MEMORY_CONSENT_REQUIRED",
                "message": "Active memory consent is required for context assembly",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_MEMORY_QUERY", "message": "Invalid memory query"},
        ) from None


@router.patch("/memory/{memory_id}")
async def update_memory(
    memory_id: str,
    request: MemoryUpdateRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        validate_personal_payload(request.value)
        if request.key is not None:
            validate_personal_payload(request.key)
        return get_app_state().memory.update(
            user["id"],
            memory_id,
            value=request.value,
            confidence=request.confidence,
            key=request.key,
            memory_type=request.memory_type,
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


@router.delete("/memory")
async def delete_all_memory(
    user: dict = Depends(get_current_user),
) -> dict:
    return {"deleted_count": get_app_state().memory.delete_all(user["id"])}


@router.post("/memory/export")
async def export_memory(
    user: dict = Depends(get_current_user),
) -> dict:
    return get_app_state().memory.export(user["id"])


@router.get("/learning/observations")
async def list_observations(
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return list(get_app_state().learning.list_observations(user["id"]))


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
        return get_app_state().learning.record_observation(
            user["id"],
            source=request.source,
            observation=request.observation,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_PERSONAL_DATA", "message": "Invalid personal data"},
        ) from None


@router.post("/learning/adaptations")
async def propose_adaptation(
    request: AdaptationRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        validate_personal_payload(request.proposal)
        return get_app_state().learning.propose_adaptation(
            user["id"],
            proposal=request.proposal,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_PERSONAL_DATA", "message": "Invalid personal data"},
        ) from None


@router.get("/learning/adaptations")
async def list_adaptations(
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return list(get_app_state().learning.list_adaptations(user["id"]))


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
