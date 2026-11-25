"""Authenticated device enrollment, confirmation, capability reporting and revocation."""
import sqlite3
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state
from backend.app.devices.contracts import (
    DeviceCapabilityReport,
    DeviceRecord,
    DeviceRegistrationRequest,
)


router = APIRouter(prefix="/devices", tags=["devices"])


class CapabilityReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    report: DeviceCapabilityReport


@router.post("", response_model=DeviceRecord, status_code=201)
async def enroll_device(
    request: DeviceRegistrationRequest,
    user: dict = Depends(get_current_user),
) -> DeviceRecord:
    try:
        # Enrollment is deliberately pending. It is not a trusted device
        # assertion and does not create a device-bound session.
        return get_app_state().devices.enroll(user["id"], request)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "DEVICE_ALREADY_ENROLLED",
                "message": "This device key fingerprint is already enrolled",
            },
        ) from None


@router.get("", response_model=list[DeviceRecord])
async def list_devices(
    user: dict = Depends(get_current_user),
) -> list[DeviceRecord]:
    return list(get_app_state().devices.list_owned(user["id"]))


@router.post("/{device_id}/confirm", response_model=DeviceRecord)
async def confirm_device(
    device_id: UUID,
    user: dict = Depends(get_current_user),
) -> DeviceRecord:
    try:
        return get_app_state().devices.confirm(user["id"], str(device_id))
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "DEVICE_NOT_FOUND", "message": "Device not found"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "DEVICE_NOT_PENDING",
                "message": "Only a pending device can be confirmed",
            },
        ) from None


@router.put("/{device_id}/capabilities", response_model=DeviceRecord)
async def report_device_capabilities(
    device_id: UUID,
    request: CapabilityReportRequest,
    user: dict = Depends(get_current_user),
) -> DeviceRecord:
    try:
        return get_app_state().devices.record_capabilities(
            user["id"],
            str(device_id),
            request.report,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "DEVICE_NOT_FOUND", "message": "Device not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "DEVICE_NOT_ACTIVE",
                "message": "Only active devices may report capabilities",
            },
        ) from None


@router.delete("/{device_id}", response_model=DeviceRecord)
async def revoke_device(
    device_id: UUID,
    user: dict = Depends(get_current_user),
) -> DeviceRecord:
    try:
        return get_app_state().devices.revoke(user["id"], str(device_id))
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "DEVICE_NOT_FOUND", "message": "Device not found"},
        ) from None
