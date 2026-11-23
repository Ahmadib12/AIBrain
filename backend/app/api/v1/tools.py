from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.tools import ToolContract, ToolExecutionGateway, ToolRegistry, ToolRisk
from backend.app.app_state import get_app_state


router = APIRouter(prefix="/tools", tags=["tools"])
tool_registry = ToolRegistry()
tool_registry.register(ToolContract(
    tool_id="echo",
    name="Safe echo",
    description="Returns bounded text without external side effects",
    risk=ToolRisk.READ_ONLY,
    input_schema={
        "type": "object",
        "properties": {
            "text": {"type": "string", "maxLength": 4096},
        },
        "required": ["text"],
        "additionalProperties": False,
    },
    output_schema={"text": {"type": "string"}},
))
def _get_tool_gateway() -> ToolExecutionGateway:
    return ToolExecutionGateway(
        tool_registry,
        get_app_state().database,
    )


class ToolProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str = Field(min_length=1, max_length=100)
    arguments: dict = Field(default_factory=dict, max_length=20)


@router.get("")
async def list_tools(
    user: dict = Depends(get_current_user),
) -> list[dict]:
    return [
        {
            "tool_id": contract.tool_id,
            "name": contract.name,
            "description": contract.description,
            "risk": contract.risk.value,
            "input_schema": contract.input_schema,
            "output_schema": contract.output_schema,
        }
        for contract in tool_registry.list()
    ]


@router.post("/execute")
async def execute_tool(
    request: ToolProposalRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        contract = tool_registry.get(request.tool_id)
        if contract is None:
            raise LookupError("Tool not found")
        if contract.risk != ToolRisk.READ_ONLY:
            raise PermissionError(
                "Use the proposal endpoint for non-read-only tools"
            )

        gateway = _get_tool_gateway()
        proposal = gateway.propose(
            user["id"],
            tool_id=request.tool_id,
            arguments=request.arguments,
        )
        return gateway.execute(proposal, user_id=user["id"])
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "TOOL_NOT_FOUND", "message": "Tool not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "CONFIRMATION_REQUIRED",
                "message": "Tool execution requires confirmation",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_TOOL_REQUEST", "message": "Invalid tool request"},
        ) from None


@router.post("/requests")
async def propose_tool(
    request: ToolProposalRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        gateway = _get_tool_gateway()
        return gateway.propose(
            user["id"],
            tool_id=request.tool_id,
            arguments=request.arguments,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "TOOL_NOT_FOUND", "message": "Tool not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "TOOL_PROPOSAL_NOT_ALLOWED",
                "message": "This tool cannot be proposed under the current authorization policy",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_TOOL_REQUEST", "message": "Invalid tool request"},
        ) from None


@router.post("/requests/{request_id}/confirm")
async def confirm_tool(
    request_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        gateway = _get_tool_gateway()
        return gateway.confirm(user["id"], request_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "TOOL_REQUEST_NOT_FOUND", "message": "Tool request not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={"code": "CONFIRMATION_NOT_AVAILABLE", "message": "Tool confirmation is unavailable"},
        ) from None


@router.post("/requests/{request_id}/cancel")
async def cancel_tool(
    request_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        gateway = _get_tool_gateway()
        return gateway.cancel(user["id"], request_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "TOOL_REQUEST_NOT_FOUND", "message": "Tool request not found"},
        ) from None
