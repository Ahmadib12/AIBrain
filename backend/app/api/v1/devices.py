"""Authenticated device enrollment, confirmation, capability reporting and revocation."""
import sqlite3
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state
from backend.app.devices.contracts import (
    DeviceCapabilityReport,
    DeviceRecord,
    DeviceRegistrationRequest,
)


router = APIRouter(prefix="/devices", tags=["devices"])


class PublicKeyRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    public_key_b64: str = Field(min_length=40, max_length=64)


class DeviceProofRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    nonce: str = Field(min_length=20, max_length=128)
    signature_b64: str = Field(min_length=80, max_length=100)


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
        device = get_app_state().devices.enroll(user["id"], request)
        return device
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


@router.put("/{device_id}/key", status_code=204)
async def register_device_public_key(
    device_id: UUID,
    request: PublicKeyRegistrationRequest,
    user: dict = Depends(get_current_user),
) -> None:
    try:
        get_app_state().device_proofs.register_public_key(
            user["id"], str(device_id), request.public_key_b64
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "PENDING_DEVICE_NOT_FOUND", "message": "Pending device not found"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "DEVICE_KEY_REJECTED", "message": "Public key does not match the enrolled fingerprint"},
        ) from None


@router.post("/{device_id}/challenge", response_model=dict)
async def create_device_challenge(
    device_id: UUID,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().device_proofs.create_challenge(
            user["id"], str(device_id)
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "PENDING_DEVICE_NOT_FOUND", "message": "Pending keyed device not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "DEVICE_CHALLENGE_RATE_LIMITED",
                "message": "Too many device challenges were requested",
            },
        ) from None


@router.post("/{device_id}/verify", status_code=204)
async def verify_device_proof(
    device_id: UUID,
    request: DeviceProofRequest,
    challenge_id: str,
    user: dict = Depends(get_current_user),
) -> None:
    try:
        get_app_state().device_proofs.verify_and_activate(
            user["id"], str(device_id), challenge_id,
            request.nonce, request.signature_b64,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "DEVICE_CHALLENGE_NOT_FOUND", "message": "Device challenge not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=401,
            detail={"code": "DEVICE_PROOF_REJECTED", "message": "Device proof could not be verified"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={"code": "DEVICE_CHALLENGE_INVALID", "message": "Device challenge is invalid, expired, or already used"},
        ) from None


@router.post("/{device_id}/session/challenge", response_model=dict)
async def create_device_session_challenge(
    device_id: UUID,
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        return get_app_state().device_proofs.create_challenge(
            user["id"], str(device_id), purpose="session"
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ACTIVE_DEVICE_NOT_FOUND",
                "message": "Active keyed device not found",
            },
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "DEVICE_CHALLENGE_RATE_LIMITED",
                "message": "Too many device challenges were requested",
            },
        ) from None


@router.post("/{device_id}/session/verify", response_model=dict)
async def verify_device_session(
    device_id: UUID,
    request: DeviceProofRequest,
    challenge_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    state = get_app_state()
    try:
        state.device_proofs.verify_session_proof(
            user["id"], str(device_id), challenge_id,
            request.nonce, request.signature_b64,
        )
        authenticated_user, token = state.identity.create_session(
            user["id"], device_id=str(device_id)
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "DEVICE_SESSION_CHALLENGE_NOT_FOUND",
                "message": "Device session challenge not found",
            },
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "DEVICE_SESSION_PROOF_REJECTED",
                "message": "Device session proof could not be verified",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "DEVICE_SESSION_CHALLENGE_INVALID",
                "message": "Device session challenge is invalid, expired, or already used",
            },
        ) from None
    return {"access_token": token, "user": authenticated_user}



@router.post("/{device_id}/login/challenge", response_model=dict)
async def create_passwordless_device_login_challenge(device_id: UUID) -> dict:
    """Start a passwordless login using an already-enrolled active device."""
    try:
        return get_app_state().device_proofs.create_login_challenge(str(device_id))
    except LookupError:
        # Unknown, pending, revoked, and unkeyed devices share one response.
        raise HTTPException(
            status_code=404,
            detail={
                "code": "DEVICE_LOGIN_UNAVAILABLE",
                "message": "Device login is unavailable",
            },
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "DEVICE_LOGIN_RATE_LIMITED",
                "message": "Too many login challenges were requested",
            },
        ) from None


@router.post("/{device_id}/login/verify", response_model=dict)
async def verify_passwordless_device_login(
    device_id: UUID,
    request: DeviceProofRequest,
    challenge_id: UUID,
) -> dict:
    """Verify device possession and issue a device-bound session."""
    state = get_app_state()
    try:
        owner_id = state.device_proofs.verify_login_proof(
            str(device_id),
            str(challenge_id),
            request.nonce,
            request.signature_b64,
        )
        # create_session performs the final account/device active-state check
        # in an IMMEDIATE transaction, closing the verification/revocation race.
        authenticated_user, token = state.identity.create_session(
            owner_id, device_id=str(device_id), auth_method="device_login"
        )
    except (LookupError, PermissionError, ValueError):
        # Keep unauthenticated proof failures indistinguishable.
        raise HTTPException(
            status_code=401,
            detail={
                "code": "DEVICE_LOGIN_REJECTED",
                "message": "Device login could not be verified",
            },
        ) from None
    return {"access_token": token, "user": authenticated_user}


@router.post("/{device_id}/confirm", response_model=DeviceRecord)
async def confirm_device(
    device_id: UUID,
    user: dict = Depends(get_current_user),
) -> DeviceRecord:
    raise HTTPException(
        status_code=409,
        detail={
            "code": "DEVICE_PROOF_REQUIRED",
            "message": "A device must prove possession of its registered private key before activation",
        },
    )


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


@router.get("/security-events", response_model=list[dict])
async def list_device_security_events(
    limit: int = 50,
    before_occurred_at: str | None = None,
    before_event_id: UUID | None = None,
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Return the authenticated owner's recent device security history."""
    try:
        return list(get_app_state().device_security_events.list_owned(
            user["id"], limit=limit,
            before_occurred_at=before_occurred_at,
            before_event_id=str(before_event_id) if before_event_id else None,
        ))
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_EVENT_PAGE_SIZE", "message": "Limit must be between 1 and 100"}) from None


@router.delete("/{device_id}", response_model=DeviceRecord)
async def revoke_device(
    device_id: UUID,
    user: dict = Depends(get_current_user),
) -> DeviceRecord:
    try:
        state = get_app_state()
        previous = state.devices.get_owned(user["id"], str(device_id))
        device = state.devices.revoke(user["id"], str(device_id))
        return device
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "DEVICE_NOT_FOUND", "message": "Device not found"},
        ) from None
