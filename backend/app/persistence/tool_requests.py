import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from backend.app.persistence.database import Database
from backend.app.persistence.validation import validate_personal_payload


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request_digest(
    tool_id: str,
    arguments: dict,
    contract_fingerprint: str | None,
) -> str:
    canonical = json.dumps(
        {
            "tool_id": tool_id,
            "arguments": arguments,
            "contract_fingerprint": contract_fingerprint,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class ToolRequestRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(
        self,
        user_id: str,
        *,
        tool_id: str,
        arguments: dict,
        status: str,
        expires_at: str | None = None,
        contract_fingerprint: str | None = None,
        authorization_policy: str = "unknown",
    ) -> dict:
        if authorization_policy not in ("unknown", "read_only", "passkey"):
            raise ValueError("Tool authorization policy is invalid")

        validate_personal_payload(arguments)
        if contract_fingerprint is not None and (
            not isinstance(contract_fingerprint, str)
            or len(contract_fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in contract_fingerprint)
        ):
            raise ValueError("Tool contract fingerprint is invalid")

        request_id = str(uuid.uuid4())
        now = _utc_now()
        proposal_digest = _request_digest(
            tool_id,
            arguments,
            contract_fingerprint,
        )
        audit = {
            "proposal": {
                "arguments_sha256": proposal_digest,
                "contract_fingerprint": contract_fingerprint,
            }
        }
        with self.database.transaction():
            self.database.connect().execute(
                "INSERT INTO tool_requests "
                "(id, user_id, tool_id, arguments_json, status, "
                "result_json, created_at, updated_at, expires_at, "
                "consumed_at, confirmation_id, audit_json, contract_fingerprint, "
                "authorization_policy) "
                "VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?, ?, ?, ?)",
                (
                    request_id,
                    user_id,
                    tool_id,
                    json.dumps(arguments, ensure_ascii=False),
                    status,
                    now,
                    now,
                    expires_at,
                    request_id,
                    json.dumps(audit, ensure_ascii=False),
                    contract_fingerprint,
                    authorization_policy,
                ),
            )
        return self.get(user_id, request_id)

    def get(self, user_id: str, request_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM tool_requests "
            "WHERE id = ? AND user_id = ?",
            (request_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Tool request not found")
        return self._row(row)

    def approve_pending(self, user_id: str, request_id: str) -> dict:
        now = datetime.now(timezone.utc)
        now_text = now.isoformat()

        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                "SELECT status, consumed_at, expires_at, audit_json, "
                "tool_id, arguments_json, contract_fingerprint, "
                "authorization_policy "
                "FROM tool_requests WHERE id = ? AND user_id = ?",
                (request_id, user_id),
            ).fetchone()

            if row is None:
                raise LookupError("Tool request not found")

            if row["authorization_policy"] != "read_only":
                raise PermissionError(
                    "Generic approval is restricted to read-only requests"
                )

            if row["status"] != "pending" or row["consumed_at"] is not None:
                raise PermissionError("Tool request is not awaiting confirmation")

            expires_at = row["expires_at"]
            if expires_at is not None:
                expiry = datetime.fromisoformat(expires_at)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry <= now:
                    raise PermissionError("Tool request has expired")

            audit = json.loads(row["audit_json"] or "{}")
            if not isinstance(audit, dict):
                raise ValueError("Tool request audit data is invalid")

            current_digest = _request_digest(
                row["tool_id"],
                json.loads(row["arguments_json"]),
                row["contract_fingerprint"],
            )
            proposal = audit.get("proposal")
            if (
                not isinstance(proposal, dict)
                or proposal.get("arguments_sha256") != current_digest
            ):
                raise PermissionError(
                    "Tool request arguments changed after proposal"
                )

            audit["confirmation"] = {
                "confirmed_at": now_text,
                "confirmed_by": user_id,
                "arguments_sha256": current_digest,
            }

            cursor = self.database.connect().execute(
                "UPDATE tool_requests "
                "SET status = 'approved', updated_at = ?, audit_json = ? "
                "WHERE id = ? AND user_id = ? "
                "AND status = 'pending' AND consumed_at IS NULL",
                (
                    now_text,
                    json.dumps(audit, ensure_ascii=False),
                    request_id,
                    user_id,
                ),
            )

            if cursor.rowcount != 1:
                raise PermissionError("Tool request is no longer awaiting confirmation")

        return self.get(user_id, request_id)

    def claim_for_execution(
        self,
        user_id: str,
        request_id: str,
        *,
        expected_contract_fingerprint: str | None = None,
    ) -> dict:
        """Atomically consume an approved request before tool dispatch."""
        now = datetime.now(timezone.utc)
        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                "SELECT * FROM tool_requests "
                "WHERE id = ? AND user_id = ?",
                (request_id, user_id),
            ).fetchone()

            if row is None:
                raise LookupError("Tool request not found")
            if row["authorization_policy"] != "read_only":
                raise PermissionError(
                    "Generic execution is restricted to read-only requests"
                )

            if row["status"] != "approved" or row["consumed_at"] is not None:
                raise PermissionError("Tool request is not available for execution")

            if expected_contract_fingerprint is not None and (
                row["contract_fingerprint"] != expected_contract_fingerprint
            ):
                raise PermissionError(
                    "Tool contract changed after proposal"
                )

            if row["expires_at"]:
                expires = datetime.fromisoformat(row["expires_at"])
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires <= now:
                    raise PermissionError("Tool request has expired")

            audit = json.loads(row["audit_json"] or "{}")
            if not isinstance(audit, dict):
                raise ValueError("Tool request audit data is invalid")
            current_digest = _request_digest(
                row["tool_id"],
                json.loads(row["arguments_json"]),
                row["contract_fingerprint"],
            )
            proposal = audit.get("proposal")
            if (
                not isinstance(proposal, dict)
                or proposal.get("arguments_sha256") != current_digest
            ):
                raise PermissionError(
                    "Tool request arguments changed after proposal"
                )

            confirmation = audit.get("confirmation")
            if confirmation is not None and (
                not isinstance(confirmation, dict)
                or confirmation.get("arguments_sha256") != current_digest
            ):
                raise PermissionError(
                    "Confirmed tool request arguments have changed"
                )

            claimed_at = now.isoformat()
            cursor = self.database.connect().execute(
                "UPDATE tool_requests "
                "SET status = 'executing', consumed_at = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ? "
                "AND status = 'approved' AND consumed_at IS NULL",
                (claimed_at, claimed_at, request_id, user_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("Tool request is not available for execution")

        return self.get(user_id, request_id)

    def complete_execution(
        self,
        user_id: str,
        request_id: str,
        *,
        result: dict,
    ) -> dict:
        validate_personal_payload(result)
        now = _utc_now()
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "UPDATE tool_requests "
                "SET status = 'completed', result_json = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ? AND status = 'executing' "
                "AND consumed_at IS NOT NULL",
                (
                    json.dumps(result, ensure_ascii=False),
                    now,
                    request_id,
                    user_id,
                ),
            )
            if cursor.rowcount != 1:
                raise PermissionError("Tool execution is no longer active")
        return self.get(user_id, request_id)

    def fail_execution(
        self,
        user_id: str,
        request_id: str,
    ) -> dict:
        now = _utc_now()
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "UPDATE tool_requests "
                "SET status = 'failed', updated_at = ? "
                "WHERE id = ? AND user_id = ? AND status = 'executing' "
                "AND consumed_at IS NOT NULL",
                (now, request_id, user_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("Tool execution is no longer active")
        return self.get(user_id, request_id)

    def cancel_pending(self, user_id: str, request_id: str) -> dict:
        now = _utc_now()
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "UPDATE tool_requests SET status = 'cancelled', "
                "updated_at = ?, consumed_at = ? "
                "WHERE id = ? AND user_id = ? "
                "AND status = 'pending'",
                (now, now, request_id, user_id),
            )
            if cursor.rowcount != 1:
                raise LookupError("Tool request not found or already completed")
        return self.get(user_id, request_id)

    def delete_all(self, user_id: str) -> int:
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "DELETE FROM tool_requests WHERE user_id = ?",
                (user_id,),
            )
        return cursor.rowcount

    @staticmethod
    def _row(row) -> dict:
        return {
            "id": row["id"],
            "tool_id": row["tool_id"],
            "arguments": json.loads(row["arguments_json"]),
            "status": row["status"],
            "result": (
                json.loads(row["result_json"])
                if row["result_json"] is not None
                else None
            ),
            "expires_at": row["expires_at"],
            "consumed_at": row["consumed_at"],
            "confirmation_id": row["confirmation_id"],
            "contract_fingerprint": row["contract_fingerprint"],
            "authorization_policy": row["authorization_policy"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
