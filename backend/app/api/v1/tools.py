from typing import Literal
import base64
import binascii
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from backend.app.api.v1.auth import get_current_user
from backend.app.auth.operator import (
    require_provider_operator,
    require_trusted_runner_ingest,
)
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


class PasskeyApprovalVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_record_id: str = Field(min_length=1, max_length=128)
    credential_record_id: str = Field(min_length=1, max_length=128)
    assertion: dict


class ToolProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str = Field(min_length=1, max_length=100)
    arguments: dict = Field(default_factory=dict, max_length=20)






class EvidencePackageIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict
    artifacts_base64: dict[str, str] = Field(min_length=1, max_length=64)


class RunnerAttestationPayloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=256)
    runner_id: str = Field(min_length=1, max_length=256)
    nonce: str = Field(min_length=32, max_length=128)
    issued_at: str = Field(min_length=1, max_length=64)
    expires_at: str = Field(min_length=1, max_length=64)


class TrustedRunnerKeyRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=256)
    runner_id: str = Field(min_length=1, max_length=256)
    public_key_base64: str = Field(min_length=40, max_length=64)
    valid_from: str = Field(min_length=1, max_length=64)
    valid_until: str = Field(min_length=1, max_length=64)
    registered_by: str = Field(min_length=1, max_length=256)


class TrustedRunnerKeyRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revoked_by: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1000)


class RunnerEvidenceAttestationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1, max_length=256)
    runner_id: str = Field(min_length=1, max_length=256)
    nonce: str = Field(min_length=32, max_length=128)
    issued_at: str = Field(min_length=1, max_length=64)
    expires_at: str = Field(min_length=1, max_length=64)
    signature: str = Field(min_length=1, max_length=256)


class EvidenceCertificationApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved_by: str = Field(min_length=1, max_length=256)
    expires_at: str = Field(min_length=1, max_length=64)


class CertificationRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revoked_by: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1000)


class ToolExecutionReconciliationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Literal["succeeded", "failed"]
    note: str = Field(min_length=1, max_length=1000)
    result: dict | None = None
    error_code: str | None = Field(default=None, max_length=64)


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


@router.post("/requests/{request_id}/passkey/options")
async def create_passkey_approval_options(
    request_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    """Create WebAuthn assertion options for this user's pending tool request."""
    try:
        return get_app_state().webauthn_service.create_tool_approval_options(
            user_id=user["id"],
            request_id=request_id,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "TOOL_REQUEST_NOT_FOUND",
                "message": "Tool request not found",
            },
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "PASSKEY_APPROVAL_UNAVAILABLE",
                "message": "Passkey approval is unavailable for this request",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_PASSKEY_APPROVAL",
                "message": "Invalid passkey approval request",
            },
        ) from None


@router.post("/requests/{request_id}/passkey/verify")
async def verify_passkey_approval(
    request_id: str,
    request: PasskeyApprovalVerifyRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    """Verify a passkey assertion and return sanitized authorization state."""
    try:
        state = get_app_state()
        state.webauthn_service.verify_tool_approval(
            user_id=user["id"],
            request_id=request_id,
            challenge_record_id=request.challenge_record_id,
            credential_record_id=request.credential_record_id,
            assertion=request.assertion,
        )
        approved_request = state.tool_requests.get(user["id"], request_id)
        return {
            "id": approved_request["id"],
            "tool_id": approved_request["tool_id"],
            "arguments": approved_request["arguments"],
            "status": approved_request["status"],
            "expires_at": approved_request["expires_at"],
        }
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "PASSKEY_APPROVAL_RESOURCE_NOT_FOUND",
                "message": "Passkey approval resource not found",
            },
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "PASSKEY_APPROVAL_REJECTED",
                "message": "Passkey approval could not be verified",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_PASSKEY_APPROVAL",
                "message": "Invalid passkey approval request",
            },
        ) from None


@router.get("/requests/{request_id}")
async def get_tool_request(
    request_id: str,
    user: dict = Depends(get_current_user),
) -> dict:
    """Return this owner's request and its execution-attempt state, if any."""
    state = get_app_state()
    try:
        request = state.tool_requests.get(user["id"], request_id)
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "TOOL_REQUEST_NOT_FOUND",
                "message": "Tool request not found",
            },
        ) from None

    try:
        attempt = state.tool_requests.get_execution_attempt(
            user["id"],
            request_id,
        )
    except LookupError:
        attempt = None

    return {
        "id": request["id"],
        "tool_id": request["tool_id"],
        "arguments": request["arguments"],
        "status": request["status"],
        "result": request["result"],
        "consumed_at": request["consumed_at"],
        "created_at": request["created_at"],
        "updated_at": request["updated_at"],
        "execution_attempt": (
            {
                "status": attempt["status"],
                "claimed_at": attempt["claimed_at"],
                "finished_at": attempt["finished_at"],
                "error_code": attempt["error_code"],
            }
            if attempt is not None
            else None
        ),
    }


@router.post("/requests/{request_id}/reconcile")
async def reconcile_tool_execution(
    request_id: str,
    request: ToolExecutionReconciliationRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    """Record the authenticated owner's manual resolution of an uncertain attempt.

    This endpoint records the owner's attestation; it does not verify the
    external system's state and never retries or dispatches the tool.
    """
    try:
        reconciled = get_app_state().tool_requests.reconcile_execution_attempt(
            user["id"],
            request_id,
            outcome=request.outcome,
            note=request.note,
            result=request.result,
            error_code=request.error_code,
        )
        return {
            "id": reconciled["id"],
            "tool_id": reconciled["tool_id"],
            "status": reconciled["status"],
            "result": reconciled["result"],
        }
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "TOOL_REQUEST_NOT_FOUND",
                "message": "Tool request not found",
            },
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "RECONCILIATION_NOT_AVAILABLE",
                "message": "Tool execution is not awaiting reconciliation",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_RECONCILIATION",
                "message": "Invalid tool execution reconciliation",
            },
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





@router.post("/runner/evidence", status_code=201)
async def ingest_runner_evidence(
    request: EvidencePackageIngestRequest,
    _runner: None = Depends(require_trusted_runner_ingest),
) -> dict:
    """Receive a bounded evidence package from the isolated runner."""
    artifacts: dict[str, bytes] = {}
    total_encoded = 0
    try:
        if len(request.artifacts_base64) > 64:
            raise ValueError("Too many evidence artifacts")
        for name, encoded in request.artifacts_base64.items():
            if not isinstance(encoded, str) or len(encoded) > 2_800_000:
                raise ValueError("Evidence artifact encoding exceeds limit")
            total_encoded += len(encoded)
            if total_encoded > 14_000_000:
                raise ValueError("Evidence package encoding exceeds limit")
            artifacts[name] = base64.b64decode(encoded, validate=True)
        package = get_app_state().tool_requests.verify_external_adapter_evidence(
            request.manifest, artifacts
        )
        return {
            "package_id": package["id"],
            "manifest_sha256": package["manifest_sha256"],
            "artifact_hashes": package["artifact_hashes"],
            "provider_id": package["provider_id"],
            "adapter_id": package["adapter_id"],
            "adapter_version": package["adapter_version"],
            "provider_scope": package["provider_scope"],
            "tool_id": package["tool_id"],
            "tool_contract_fingerprint": package["tool_contract_fingerprint"],
            "sandbox_environment": package["sandbox_environment"],
            "verified_at": package["verified_at"],
            "expires_at": package["expires_at"],
            "provenance": package["provenance"],
        }
    except (ValueError, binascii.Error):
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_RUNNER_EVIDENCE", "message": "Runner evidence package was rejected"},
        ) from None


@router.post("/runner/evidence/{package_id}/attestation-payload")
async def get_runner_attestation_payload(
    package_id: str,
    request: RunnerAttestationPayloadRequest,
    _runner: None = Depends(require_trusted_runner_ingest),
) -> dict:
    """Return the exact payload the isolated runner must sign locally."""
    try:
        return get_app_state().tool_requests.build_external_adapter_evidence_attestation_payload(
            package_id,
            key_id=request.key_id,
            runner_id=request.runner_id,
            nonce=request.nonce,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "EVIDENCE_OR_KEY_NOT_FOUND", "message": "Evidence package or trusted runner key not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={"code": "RUNNER_ATTESTATION_UNAVAILABLE", "message": "Runner attestation cannot be issued for this package"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_RUNNER_ATTESTATION_REQUEST", "message": "Invalid runner attestation request"},
        ) from None


@router.post("/operator/trusted-runner-keys", status_code=201)
async def register_trusted_runner_key(
    request: TrustedRunnerKeyRegistrationRequest,
    _operator: None = Depends(require_provider_operator),
) -> dict:
    """Register an externally generated Ed25519 public key."""
    try:
        public_key = base64.b64decode(
            request.public_key_base64, validate=True
        )
        key = get_app_state().tool_requests.register_trusted_runner_key(
            key_id=request.key_id,
            runner_id=request.runner_id,
            public_key=public_key,
            valid_from=request.valid_from,
            valid_until=request.valid_until,
            registered_by=request.registered_by,
        )
        return {
            "key_id": key["key_id"],
            "runner_id": key["runner_id"],
            "algorithm": key["algorithm"],
            "valid_from": key["valid_from"],
            "valid_until": key["valid_until"],
            "created_at": key["created_at"],
        }
    except (ValueError, binascii.Error):
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_RUNNER_KEY", "message": "Invalid trusted runner key"},
        ) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail={"code": "RUNNER_KEY_CONFLICT", "message": "Runner key identifier or public key is already registered"},
        ) from None


@router.post("/operator/trusted-runner-keys/{key_id}/revoke")
async def revoke_trusted_runner_key(
    key_id: str,
    request: TrustedRunnerKeyRevocationRequest,
    _operator: None = Depends(require_provider_operator),
) -> dict:
    try:
        get_app_state().tool_requests.revoke_trusted_runner_key(
            key_id, revoked_by=request.revoked_by, reason=request.reason
        )
        return {"key_id": key_id, "status": "revoked"}
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "RUNNER_KEY_NOT_FOUND", "message": "Trusted runner key not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={"code": "RUNNER_KEY_ALREADY_REVOKED", "message": "Trusted runner key is already revoked"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_RUNNER_KEY_REVOCATION", "message": "Invalid key revocation request"},
        ) from None


@router.post("/runner/evidence/{package_id}/attest")
async def attest_external_adapter_evidence(
    package_id: str,
    request: RunnerEvidenceAttestationRequest,
    _runner: None = Depends(require_trusted_runner_ingest),
) -> dict:
    try:
        attestation = get_app_state().tool_requests.attest_external_adapter_evidence(
            package_id,
            key_id=request.key_id,
            runner_id=request.runner_id,
            nonce=request.nonce,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
            signature=request.signature,
        )
        return {
            "package_id": attestation["package_id"],
            "key_id": attestation["key_id"],
            "runner_id": attestation["runner_id"],
            "payload_sha256": attestation["payload_sha256"],
            "verified_at": attestation["verified_at"],
        }
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "EVIDENCE_OR_KEY_NOT_FOUND", "message": "Evidence package or trusted runner key not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={"code": "RUNNER_ATTESTATION_REJECTED", "message": "Runner attestation could not be verified"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_RUNNER_ATTESTATION", "message": "Invalid runner attestation"},
        ) from None


@router.post("/operator/evidence/{package_id}/certify", status_code=201)
async def certify_external_adapter_evidence(
    package_id: str,
    request: EvidenceCertificationApprovalRequest,
    _operator: None = Depends(require_provider_operator),
) -> dict:
    try:
        certificate = get_app_state().tool_requests.certify_external_adapter(
            evidence_package_id=package_id,
            approved_by=request.approved_by,
            expires_at=request.expires_at,
        )
        return {
            "id": certificate["id"],
            "provider_id": certificate["provider_id"],
            "adapter_id": certificate["adapter_id"],
            "adapter_version": certificate["adapter_version"],
            "provider_scope": certificate["provider_scope"],
            "tool_id": certificate["tool_id"],
            "test_report_sha256": certificate["test_report_sha256"],
            "expires_at": certificate["expires_at"],
            "approved_by": certificate["approved_by"],
        }
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "EVIDENCE_PACKAGE_NOT_FOUND", "message": "Evidence package not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={"code": "EVIDENCE_CERTIFICATION_REJECTED", "message": "Evidence package is not eligible for certification"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_EVIDENCE_CERTIFICATION", "message": "Invalid certification request"},
        ) from None


@router.post("/operator/certifications/{certification_id}/revoke")
async def revoke_external_adapter_certification(
    certification_id: str,
    request: CertificationRevocationRequest,
    _operator: None = Depends(require_provider_operator),
) -> dict:
    try:
        get_app_state().tool_requests.revoke_external_adapter_certification(
            certification_id,
            revoked_by=request.revoked_by,
            reason=request.reason,
        )
        return {"certification_id": certification_id, "status": "revoked"}
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={"code": "CERTIFICATION_NOT_FOUND", "message": "Adapter certification not found"},
        ) from None
    except PermissionError:
        raise HTTPException(
            status_code=409,
            detail={"code": "CERTIFICATION_ALREADY_REVOKED", "message": "Adapter certification is already revoked"},
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_CERTIFICATION_REVOCATION", "message": "Invalid certification revocation"},
        ) from None
