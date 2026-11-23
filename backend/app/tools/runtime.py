from datetime import datetime, timedelta, timezone

from backend.app.tools.contracts import (
    ToolContract,
    ToolRegistry,
    ToolRisk,
    contract_fingerprint,
)
from backend.app.persistence.database import Database
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.tools.validation import validate_tool_arguments


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ToolExecutionGateway:
    def __init__(
        self,
        registry: ToolRegistry,
        database: Database | None = None,
        *,
        confirmation_ttl_seconds: int = 300,
    ) -> None:
        self.registry = registry
        self.database = database
        self.confirmation_ttl_seconds = confirmation_ttl_seconds
        self._tool_requests = (
            ToolRequestRepository(database)
            if database is not None
            else None
        )

    def propose(
        self,
        user_id: str,
        *,
        tool_id: str,
        arguments: dict,
    ) -> dict:
        contract = self.registry.get(tool_id)
        if contract is None:
            raise LookupError("Tool not found")
        if contract.risk == ToolRisk.CONSEQUENTIAL:
            raise PermissionError(
                "Consequential tools require a stronger authorization policy"
            )
        if contract.risk not in (ToolRisk.READ_ONLY, ToolRisk.STATE_CHANGE):
            raise PermissionError("Unsupported tool risk level")
        if self._tool_requests is None:
            raise PermissionError(
                "Persistent tool request storage is required"
            )
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be an object")

        validate_tool_arguments(contract.input_schema, arguments)

        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(seconds=self.confirmation_ttl_seconds)
        ).isoformat()

        request = self._tool_requests.create(
            user_id,
            tool_id=tool_id,
            arguments=arguments,
            status=(
                "approved"
                if contract.risk == ToolRisk.READ_ONLY
                else "pending"
            ),
            expires_at=expires_at,
            contract_fingerprint=contract_fingerprint(contract),
            authorization_policy=(
                "read_only"
                if contract.risk == ToolRisk.READ_ONLY
                else "passkey"
            ),
        )
        return {
            "id": request["id"],
            "user_id": user_id,
            "tool_id": request["tool_id"],
            "arguments": request["arguments"],
            "status": request["status"],
            "created_at": request["created_at"],
        }

    def execute(self, proposal: dict, *, user_id: str | None = None) -> dict:
        if not isinstance(proposal, dict):
            raise ValueError("Tool proposal must be an object")
        if not isinstance(user_id, str) or not user_id:
            raise PermissionError("An authenticated user is required")
        if proposal.get("user_id") != user_id:
            raise PermissionError("Tool proposal belongs to another user")
        if self._tool_requests is None:
            raise PermissionError(
                "Persistent tool request storage is required"
            )

        request_id = proposal.get("id")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("Tool request ID is invalid")

        # The persisted request, not caller-supplied fields, is authoritative.
        persisted = self._tool_requests.get(user_id, request_id)
        contract = self.registry.get(persisted["tool_id"])
        if contract is None:
            raise LookupError("Tool not found")
        if contract.risk != ToolRisk.READ_ONLY:
            raise PermissionError(
                "This tool requires a complete confirmation policy"
            )

        current_fingerprint = contract_fingerprint(contract)
        if persisted["contract_fingerprint"] != current_fingerprint:
            raise PermissionError(
                "Tool contract changed after proposal"
            )

        validate_tool_arguments(contract.input_schema, persisted["arguments"])

        claimed = self._tool_requests.claim_for_execution(
            user_id,
            request_id,
            expected_contract_fingerprint=current_fingerprint,
        )

        try:
            if contract.tool_id == "echo":
                value = claimed["arguments"].get("text")
                if not isinstance(value, str) or len(value) > 4_096:
                    raise ValueError(
                        "Echo text must be a string up to 4096 characters"
                    )
                result = {
                    "status": "completed",
                    "result": {"text": value},
                }
            else:
                raise LookupError("Tool implementation not available")
        except Exception:
            self._tool_requests.fail_execution(user_id, request_id)
            raise

        self._tool_requests.complete_execution(
            user_id,
            request_id,
            result=result,
        )
        return result

    def confirm(
        self,
        user_id: str,
        request_id: str,
    ) -> dict:
        if self._tool_requests is None:
            raise LookupError("Tool request storage is unavailable")

        # Check ownership before refusing confirmation, so another user's
        # request is not disclosed through this endpoint.
        persisted = self._tool_requests.get(user_id, request_id)
        contract = self.registry.get(persisted["tool_id"])

        if contract is None:
            raise LookupError("Tool not found")

        if contract.risk != ToolRisk.STATE_CHANGE:
            raise PermissionError(
                "This confirmation flow only supports state-changing tools"
            )

        # An authenticated session alone is not proof of deliberate human
        # authorization. Keep state-changing requests pending until a
        # proposal-bound authorization mechanism is implemented.
        raise PermissionError(
            "Human authorization is not implemented"
        )

    def cancel(
        self,
        user_id: str,
        request_id: str,
    ) -> dict:
        if self._tool_requests is None:
            raise LookupError("Tool request storage is unavailable")
        return self._tool_requests.cancel_pending(user_id, request_id)
