import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state


router = APIRouter(prefix="/agents", tags=["agents"])


class AgentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    metadata: dict = Field(default_factory=dict)


@router.post("", status_code=201)
async def register_agent(
    request: AgentCreateRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().agents.create(
            user["id"],
            name=request.name,
            description=request.description,
            metadata=request.metadata,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_AGENT",
                "message": "Agent registration details are invalid",
            },
        ) from None
    except LookupError:
        raise HTTPException(
            status_code=401,
            detail={"code": "UNAUTHORIZED", "message": "The owner account is not active"},
        ) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=401,
            detail={"code": "UNAUTHORIZED", "message": "The owner account is not active"},
        ) from None


@router.get("")
async def list_agents(
    limit: int = Query(default=100, ge=1, le=100),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return get_app_state().agents.list(user["id"], limit=limit)


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().agents.get(user["id"], agent_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "AGENT_NOT_FOUND", "message": "Agent not found"},
        ) from None


@router.get("/{agent_id}/events")
async def list_agent_events(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=100),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    try:
        return get_app_state().agents.list_events(
            user["id"],
            agent_id,
            limit=limit,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "AGENT_NOT_FOUND", "message": "Agent not found"},
        ) from None
