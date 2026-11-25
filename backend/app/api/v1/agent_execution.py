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
from backend.app.intelligence.classifier import DeterministicTaskClassifier
from backend.app.intelligence.planning.agent_bridge import PlanRunProposalBridge
from backend.app.intelligence.planning.engine import PlanningEngine


router = APIRouter(tags=["agent-execution"])


def _error(status: int, code: str, message: str):
    raise HTTPException(status_code=status, detail={"code": code, "message": message})


class AgentRunActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_id: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    required_capability: str | None = Field(default=None, min_length=1, max_length=80)
    connection_id: str | None = Field(default=None, min_length=1, max_length=80)


class AgentRunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actions: list[AgentRunActionRequest] = Field(min_length=1, max_length=10)


class PlanActionMappingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_task_id: str = Field(min_length=1, max_length=64)
    tool_id: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    required_capability: str = Field(min_length=1, max_length=80)


class AgentPlanRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=500)
    actions: list[PlanActionMappingRequest] = Field(min_length=1, max_length=10)


def _reject_unbound_integration_actions(actions, state) -> None:
    for action in actions:
        if state.integrations.resolve_tool(action["tool_id"]) is not None:
            raise PermissionError(
                "Integration tools require the dedicated bound asynchronous orchestrator"
            )


def _integration_run_requested(actions, state) -> bool:
    selected = [
        state.integrations.resolve_tool(action["tool_id"]) is not None
        for action in actions
    ]
    if any(selected) and not all(selected):
        raise PermissionError("Mixed integration and non-integration runs are not permitted")
    if all(selected):
        if any(not action.get("connection_id") for action in actions):
            raise ValueError("Every integration action requires an owner connection")
        return True
    if any(action.get("connection_id") is not None for action in actions):
        raise ValueError("Connection IDs are only valid for registered integration tools")
    return False


def _runtime():
    # Import lazily to avoid coupling router registration to the tools API.
    from backend.app.api.v1.tools import _get_tool_gateway, tool_registry
    return tool_registry, _get_tool_gateway()


@router.post("/agent-tasks/{task_id}/plan-runs", status_code=201)
async def create_planned_agent_run(
    task_id: str,
    request: AgentPlanRunRequest,
    user: dict = Depends(get_current_user),
):
    """Create a durable M9 proposal from a deterministic bounded plan.

    The endpoint never authorizes or executes the resulting run. The owner
    must use the separate authorize and execute endpoints.
    """
    try:
        classifier = DeterministicTaskClassifier()
        classification = classifier.classify(request.text)
        state = get_app_state()
        task = state.agent_control.get_task(user["id"], task_id)
        planning = PlanningEngine().plan(
            request.text,
            classification,
            available_capabilities=task["capability_ceiling"],
        )
        registry, _ = _runtime()
        run = PlanRunProposalBridge().create_proposal(
            user["id"],
            task_id,
            planning,
            [item.model_dump() for item in request.actions],
            repository=state.agent_execution,
            registry=registry,
        )
        return {
            "intent": planning.intent.model_dump(mode="json"),
            "plan": planning.plan.model_dump(mode="json"),
            "assessment": planning.assessment.model_dump(mode="json"),
            "run": run,
            "execution_authorized": False,
            "execution_started": False,
        }
    except LookupError:
        _error(404, "AGENT_TASK_OR_TOOL_NOT_FOUND", "Agent task or tool not found")
    except PermissionError:
        _error(403, "AGENT_PLAN_NOT_PERMITTED", "The plan exceeds current agent authority")
    except ValueError:
        _error(400, "INVALID_AGENT_PLAN", "The plan or action mapping is invalid")
    except sqlite3.IntegrityError:
        _error(409, "AGENT_PLAN_CONFLICT", "The plan proposal could not be persisted")


@router.post("/agent-tasks/{task_id}/runs", status_code=201)
async def create_agent_run(
    task_id: str,
    request: AgentRunCreateRequest,
    user: dict = Depends(get_current_user),
):
    try:
        state = get_app_state()
        actions = [item.model_dump() for item in request.actions]
        if _integration_run_requested(actions, state):
            return state.agent_execution.create_integration_run(
                user["id"], task_id, actions,
                state.integrations, state.integration_connections,
            )
        registry, _ = _runtime()
        ordinary_actions = [
            {key: value for key, value in action.items() if key != "connection_id"}
            for action in actions
        ]
        return state.agent_execution.create_run(
            user["id"], task_id, ordinary_actions, registry
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
        state = get_app_state()
        run = state.agent_execution.get_run(user["id"], run_id)
        if any("integration_binding" in action for action in run["actions"]):
            return await state.integration_orchestrator.execute_run(user["id"], run_id)
        registry, gateway = _runtime()
        return state.agent_execution.execute_run(
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
