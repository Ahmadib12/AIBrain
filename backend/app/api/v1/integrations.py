"""Owner-facing integration catalog and explicit consent lifecycle.

This API creates pending consent records only. It has no endpoint capable of
asserting provider verification, activating credentials, or dispatching tools.
"""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state
from backend.app.tools.integrations import IntegrationRegistry


router = APIRouter(prefix="/integrations", tags=["integrations"])
integration_registry = IntegrationRegistry()


class IntegrationConsentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scopes: list[str] = Field(min_length=1, max_length=30)


@router.get("/catalog")
async def list_integration_catalog(user: dict = Depends(get_current_user)) -> list[dict]:
    # Authentication is required even for catalog discovery so the same
    # permission boundary applies to all integration-management operations.
    return integration_registry.catalog()


@router.get("/connections")
async def list_integration_connections(user: dict = Depends(get_current_user)) -> list[dict]:
    return get_app_state().integration_connections.list_for_owner(user["id"])


@router.post("/{integration_id}/connections", status_code=201)
async def request_integration_connection(
    integration_id: str,
    request: IntegrationConsentRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    manifest = integration_registry.get(integration_id)
    if manifest is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "INTEGRATION_NOT_FOUND", "message": "Integration is not registered"},
        )
    allowed_scopes = {
        scope for tool in manifest.tools for scope in tool.required_scopes
    }
    if len(request.scopes) != len(set(request.scopes)) or not set(request.scopes).issubset(allowed_scopes):
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_INTEGRATION_SCOPES", "message": "Requested scopes exceed the registered integration contract"},
        )
    try:
        return get_app_state().integration_connections.create_pending(
            user["id"],
            integration_id,
            request.scopes,
            consent_version=manifest.version,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "OWNER_NOT_FOUND", "message": "Account is not available"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_INTEGRATION_CONSENT", "message": "Integration consent is invalid"},
        ) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail={"code": "INTEGRATION_CONNECTION_CONFLICT", "message": "Connection could not be created"},
        ) from None


@router.post("/connections/{connection_id}/revoke")
async def revoke_integration_connection(
    connection_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().integration_connections.revoke(user["id"], connection_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "INTEGRATION_CONNECTION_NOT_FOUND", "message": "Connection not found"},
        ) from None


@router.post("/connections/{connection_id}/disconnect")
async def disconnect_integration_connection(
    connection_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().integration_connections.disconnect(user["id"], connection_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "INTEGRATION_CONNECTION_NOT_FOUND", "message": "Connection not found"},
        ) from None
