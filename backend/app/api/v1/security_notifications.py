"""Security-operator endpoints for notification dead letters and monitoring."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.app.auth.operator import require_security_operator
from backend.app.app_state import get_app_state


router = APIRouter(prefix="/security-notifications", tags=["security-notifications"])


class RedriveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reason: str = Field(min_length=10, max_length=500)


@router.get("/metrics", response_model=dict)
async def notification_metrics(
    _operator: dict = Depends(require_security_operator),
) -> dict:
    state = get_app_state()
    return {
        "notifications": state.security_notification_operations.metrics(),
        "recovery_abuse": state.security_recovery_abuse.metrics(),
    }


@router.get("/dead-letter", response_model=list[dict])
async def list_dead_letters(
    limit: int = 50,
    _operator: dict = Depends(require_security_operator),
) -> list[dict]:
    try:
        return list(get_app_state().security_notification_operations.list_dead_letters(limit=limit))
    except ValueError:
        raise HTTPException(status_code=422, detail={
            "code": "INVALID_PAGE_SIZE", "message": "Limit must be between 1 and 100"
        }) from None


@router.get("/dead-letter/{notification_id}/events", response_model=list[dict])
async def dead_letter_events(
    notification_id: UUID,
    limit: int = 50,
    _operator: dict = Depends(require_security_operator),
) -> list[dict]:
    try:
        return list(get_app_state().security_notification_operations.notification_events(
            str(notification_id), limit=limit
        ))
    except ValueError:
        raise HTTPException(status_code=422, detail={
            "code": "INVALID_PAGE_SIZE", "message": "Limit must be between 1 and 100"
        }) from None


@router.post("/dead-letter/{notification_id}/redrive", response_model=dict)
async def redrive_dead_letter(
    notification_id: UUID,
    request: RedriveRequest,
    operator: dict = Depends(require_security_operator),
) -> dict:
    try:
        changed = get_app_state().security_notification_operations.redrive(
            str(notification_id), operator_user_id=operator["id"], reason=request.reason
        )
    except ValueError:
        raise HTTPException(status_code=422, detail={
            "code": "INVALID_REDRIVE_REASON", "message": "A reason of 10 to 500 characters is required"
        }) from None
    if not changed:
        raise HTTPException(status_code=404, detail={
            "code": "DEAD_LETTER_NOT_FOUND", "message": "Failed notification not found"
        })
    return {"status": "queued", "notification_id": str(notification_id)}
