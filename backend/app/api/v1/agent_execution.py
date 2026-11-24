"""Owner-authorized agent run lifecycle.

This API deliberately exposes only read-only tool execution. State-changing and
consequential operations remain behind the existing protected tool workflows.
"""
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state


router = APIRouter(tags=["agent-execution"])


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"code": code, "message": message})


class AgentRunActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_id: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    required_capability: str | None = Field(default=None, min_length=1, max_length=80)


class AgentRunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actions: list[AgentRunActionRequest] = Field(min_length=1, max_length=10)


def _reject_unbound_integration_actions(actions, state) -> None:
    for action in actions:
        if state.integrations.resolve_tool(action["tool_id"]) is not None:
            raise PermissionError(
                "Integration tools require the dedicated bound asynchronous orchestrator"
            )


def _runtime():
    # Import lazily to avoid coupling router registration to the tools API.
    from backend.app.api.v1.tools import _get_tool_gateway, tool_registry
    return tool_registry, _get_tool_gateway()


@router.post("/agent-tasks/{task_id}/runs", status_code=201)
async def create_agent_run(
    task_id: str,
    request: AgentRunCreateRequest,
    user: dict = Depends(get_current_user),
):
    try:
        state = get_app_state()
        actions = [item.model_dump() for item in request.actions]
        _reject_unbound_integration_actions(actions, state)
        registry, _ = _runtime()
        return state.agent_execution.create_run(
            user["id"], task_id, actions, registry
        )
    except LookupError:
        _error(404, "AGENT_TASK_OR_TOOL_NOT_FOUND", "Agent task or tool not found")
    except PermissionError:
        _error(403, "AGENT_RUN_NOT_PERMITTED", "The run exceeds current agent authority")
    except ValueError:
        _error(400, "INVALID_AGENT_RUN", "The run definition is invalid")
    except sqlite3.IntegrityError:
        _error(409, "AGENT_RUN_CONFLICT", "The run could not be persisted")


@router.get("/agent-runs/{run_id}")
async def get_agent_run(run_id: str, user: dict = Depends(get_current_user)):
    try:
        return get_app_state().agent_execution.get_run(user["id"], run_id)
    except LookupError:
        _error(404, "AGENT_RUN_NOT_FOUND", "Agent run not found")


@router.get("/agent-runs/{run_id}/events")
async def get_agent_run_events(
    run_id: str,
    limit: int = Query(default=100, ge=1, le=100),
    user: dict = Depends(get_current_user),
):
    try:
        return get_app_state().agent_execution.list_events(user["id"], run_id, limit)
    except LookupError:
        _error(404, "AGENT_RUN_NOT_FOUND", "Agent run not found")


@router.post("/agent-runs/{run_id}/authorize")
async def authorize_agent_run(run_id: str, user: dict = Depends(get_current_user)):
    try:
        state = get_app_state()
        return state.agent_execution.authorize_run(
            user["id"], run_id, state.integrations, state.integration_connections
        )
    except LookupError:
        _error(404, "AGENT_RUN_NOT_FOUND", "Agent run not found")
    except PermissionError:
        _error(403, "AGENT_RUN_AUTHORIZATION_REJECTED", "Current policy does not permit this run")
    except ValueError:
        _error(409, "AGENT_RUN_NOT_AUTHORIZABLE", "Only a proposed run can be authorized")
    except sqlite3.IntegrityError:
        _error(409, "AGENT_RUN_CONFLICT", "Run authorization conflicted with persisted state")


@router.post("/agent-runs/{run_id}/execute")
async def execute_agent_run(run_id: str, user: dict = Depends(get_current_user)):
    try:
        registry, gateway = _runtime()
        return get_app_state().agent_execution.execute_run(
            user["id"], run_id, gateway, registry
        )
    except LookupError:
        _error(404, "AGENT_RUN_OR_TOOL_NOT_FOUND", "Agent run or tool not found")
    except PermissionError:
        _error(403, "AGENT_RUN_EXECUTION_REJECTED", "Current policy does not permit execution")
    except ValueError:
        _error(409, "AGENT_RUN_NOT_EXECUTABLE", "The run is not authorized or executable")
    except sqlite3.IntegrityError:
        _error(409, "AGENT_RUN_CONFLICT", "Run execution conflicted with persisted state")


@router.post("/agent-runs/{run_id}/cancel")
async def cancel_agent_run(run_id: str, user: dict = Depends(get_current_user)):
    try:
        return get_app_state().agent_execution.cancel_run(user["id"], run_id)
    except LookupError:
        _error(404, "AGENT_RUN_NOT_FOUND", "Agent run not found")
    except ValueError:
        _error(409, "AGENT_RUN_NOT_CANCELLABLE", "Only unstarted runs can be cancelled")
    except sqlite3.IntegrityError:
        _error(409, "AGENT_RUN_CONFLICT", "Run cancellation conflicted with persisted state")


@router.post("/agent-runs/reconcile-expired")
async def reconcile_expired_agent_runs(user: dict = Depends(get_current_user)):
    return {
        "expired": get_app_state().agent_execution.reconcile_expired_runs(user["id"])
    }
