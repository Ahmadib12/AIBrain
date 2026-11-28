import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state
from backend.app.persistence.agent_control import CAPABILITIES, CAPABILITY_CATALOG_VERSION


router = APIRouter(tags=["agent-control"])


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"code": code, "message": message})


class GrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability: str = Field(min_length=1, max_length=80)
    expires_at: str | None = None


class RevokeGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="", max_length=500)


class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    goal: str = Field(default="", max_length=4000)
    context: dict[str, Any] = Field(default_factory=dict)
    capability_ceiling: list[str] = Field(default_factory=list, max_length=20)
    expires_at: str


class TaskTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(min_length=1, max_length=30)
    reason: str = Field(default="", max_length=500)


class TaskClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    worker_id: str = Field(min_length=1, max_length=100)
    lease_seconds: int = Field(default=300, ge=30, le=3600)


class TaskHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    worker_id: str = Field(min_length=1, max_length=100)
    lease_seconds: int = Field(default=300, ge=30, le=3600)


class MessageCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient_agent_id: str = Field(min_length=1, max_length=100)
    task_id: str | None = None
    payload: dict[str, Any]


@router.post("/agents/{agent_id}/capabilities", status_code=201)
async def grant_agent_capability(
    agent_id: str, request: GrantRequest,
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.grant(
            user["id"], agent_id, request.capability, request.expires_at
        )
    except LookupError:
        _error(404, "AGENT_NOT_FOUND", "Agent or grant not found")
    except ValueError:
        _error(400, "INVALID_CAPABILITY_GRANT", "Capability grant is invalid")
    except sqlite3.IntegrityError:
        _error(409, "INVALID_CAPABILITY_GRANT", "Capability grant is not permitted")


@router.get("/agents/{agent_id}/capabilities")
async def list_agent_capabilities(
    agent_id: str, user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.list_grants(user["id"], agent_id)
    except LookupError:
        _error(404, "AGENT_NOT_FOUND", "Agent not found")


@router.delete("/agents/{agent_id}/capabilities/{grant_id}")
async def revoke_agent_capability(
    agent_id: str, grant_id: str,
    request: RevokeGrantRequest,
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.revoke(
            user["id"], agent_id, grant_id, request.reason
        )
    except LookupError:
        _error(404, "GRANT_NOT_FOUND", "Grant not found")
    except ValueError:
        _error(409, "GRANT_ALREADY_REVOKED", "Grant cannot be revoked")
    except sqlite3.IntegrityError:
        _error(409, "INVALID_GRANT_REVOCATION", "Grant cannot be revoked")


@router.post("/agents/{agent_id}/tasks", status_code=201)
async def create_agent_task(
    agent_id: str, request: TaskCreateRequest,
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.create_task(
            user["id"], agent_id, title=request.title, goal=request.goal,
            context=request.context, capability_ceiling=request.capability_ceiling,
            expires_at=request.expires_at,
        )
    except LookupError:
        _error(404, "AGENT_NOT_FOUND", "Agent not found")
    except ValueError:
        _error(400, "INVALID_AGENT_TASK", "Task details or capability ceiling are invalid")
    except sqlite3.IntegrityError:
        _error(409, "INVALID_AGENT_TASK", "Task assignment is not permitted")


@router.get("/agents/{agent_id}/tasks")
async def list_agent_tasks(
    agent_id: str, limit: int = Query(default=100, ge=1, le=100),
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.list_tasks(user["id"], agent_id, limit)
    except LookupError:
        _error(404, "AGENT_NOT_FOUND", "Agent not found")


@router.get("/agent-tasks/{task_id}")
async def get_agent_task(task_id: str, user: dict = Depends(get_current_user)):
    try:
        return get_app_state().agent_control.get_task(user["id"], task_id)
    except LookupError:
        _error(404, "TASK_NOT_FOUND", "Task not found")


@router.patch("/agent-tasks/{task_id}/lifecycle")
async def transition_agent_task(
    task_id: str, request: TaskTransitionRequest,
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.transition_task(
            user["id"], task_id, request.status, request.reason
        )
    except LookupError:
        _error(404, "TASK_NOT_FOUND", "Task not found")
    except ValueError:
        _error(409, "INVALID_TASK_TRANSITION", "Task transition is not permitted")
    except sqlite3.IntegrityError:
        _error(409, "INVALID_TASK_TRANSITION", "Task transition is not permitted")


@router.post("/agents/{agent_id}/agent-tasks/{task_id}/claim", status_code=200)
async def claim_agent_task(
    agent_id: str,
    task_id: str,
    request: TaskClaimRequest,
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.claim_task(
            user["id"],
            agent_id,
            task_id,
            worker_id=request.worker_id,
            lease_seconds=request.lease_seconds,
        )
    except LookupError:
        _error(404, "AGENT_OR_TASK_NOT_FOUND", "Agent or task not found")
    except ValueError:
        _error(409, "TASK_NOT_CLAIMABLE", "The task is unavailable or already claimed")


@router.post("/agents/{agent_id}/agent-tasks/{task_id}/heartbeat", status_code=200)
async def heartbeat_agent_task(
    agent_id: str,
    task_id: str,
    request: TaskHeartbeatRequest,
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.heartbeat_task(
            user["id"],
            agent_id,
            task_id,
            worker_id=request.worker_id,
            lease_seconds=request.lease_seconds,
        )
    except LookupError:
        _error(404, "AGENT_OR_TASK_NOT_FOUND", "Agent or task not found")
    except PermissionError:
        _error(403, "TASK_LEASE_NOT_OWNED", "Worker does not own this task lease")
    except ValueError:
        _error(409, "TASK_HEARTBEAT_REJECTED", "The task lease cannot be renewed")


@router.post("/agents/{agent_id}/messages", status_code=201)
async def send_agent_message(
    agent_id: str, request: MessageCreateRequest,
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.send_message(
            user["id"], agent_id, request.recipient_agent_id,
            request.payload, request.task_id,
        )
    except LookupError:
        _error(404, "AGENT_OR_TASK_NOT_FOUND", "Agent or task not found")
    except ValueError:
        _error(400, "INVALID_AGENT_MESSAGE", "Message is invalid")
    except sqlite3.IntegrityError:
        _error(409, "INVALID_AGENT_MESSAGE", "Message participants or task are invalid")


@router.get("/agents/{agent_id}/messages")
async def list_agent_messages(
    agent_id: str, limit: int = Query(default=100, ge=1, le=100),
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.list_messages(user["id"], agent_id, limit)
    except LookupError:
        _error(404, "AGENT_NOT_FOUND", "Agent not found")


@router.get("/agents/{agent_id}/control-events")
async def list_agent_control_events(
    agent_id: str, limit: int = Query(default=100, ge=1, le=100),
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.list_events(user["id"], agent_id, limit)
    except LookupError:
        _error(404, "AGENT_NOT_FOUND", "Agent not found")



@router.get("/agent-capabilities/catalog")
async def get_agent_capability_catalog(user: dict = Depends(get_current_user)):
    return {
        "version": CAPABILITY_CATALOG_VERSION,
        "capabilities": sorted(CAPABILITIES),
        "execution_enabled": False,
    }


@router.get("/agent-tasks/{task_id}/events")
async def list_agent_task_events(
    task_id: str, limit: int = Query(default=100, ge=1, le=100),
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_control.list_task_events(
            user["id"], task_id, limit
        )
    except LookupError:
        _error(404, "TASK_NOT_FOUND", "Task not found")


@router.post("/agent-tasks/reconcile-expired")
async def reconcile_expired_agent_tasks(user: dict = Depends(get_current_user)):
    # Owner-scoped reconciliation only; no executor is invoked.
    state = get_app_state()
    expired = state.agent_control.reconcile_expired_tasks(user["id"])
    requeued = state.agent_control.reconcile_stale_task_claims(user["id"])
    return {"expired": expired, "requeued": requeued}
