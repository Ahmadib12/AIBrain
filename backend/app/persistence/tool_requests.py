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
        """Atomically consume an approved request and persist its execution attempt."""
        now = datetime.now(timezone.utc)
        now_text = now.isoformat()
        attempt_id = str(uuid.uuid4())

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
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
                raise PermissionError("Tool contract changed after proposal")

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

            claimed = connection.execute(
                "UPDATE tool_requests "
                "SET status = 'executing', consumed_at = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ? "
                "AND status = 'approved' AND consumed_at IS NULL",
                (now_text, now_text, request_id, user_id),
            )
            if claimed.rowcount != 1:
                raise PermissionError("Tool request is not available for execution")

            # The request claim and attempt record share this transaction.
            # The request ID is the stable idempotency key for its single attempt.
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key,
                    status, claimed_at, updated_at
                ) VALUES (?, ?, ?, ?, 'claimed', ?, ?)
                """,
                (
                    attempt_id,
                    user_id,
                    request_id,
                    request_id,
                    now_text,
                    now_text,
                ),
            )

        return self.get(user_id, request_id)

    def create_execution_binding(
        self,
        user_id: str,
        request_id: str,
        *,
        idempotency_key: str,
        action_digest: str,
        payload: dict,
        tool_contract_fingerprint: str,
        adapter_id: str,
        adapter_version: str,
        provider_id: str,
        provider_scope: str,
        capabilities: dict,
    ) -> dict:
        """Persist the immutable provider/action binding for an already claimed request."""
        identifiers = {
            "idempotency_key": idempotency_key,
            "action_digest": action_digest,
            "tool_contract_fingerprint": tool_contract_fingerprint,
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "provider_id": provider_id,
            "provider_scope": provider_scope,
        }
        for name, value in identifiers.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("action_digest", "tool_contract_fingerprint"):
            value = identifiers[name]
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if not isinstance(payload, dict) or not isinstance(capabilities, dict):
            raise ValueError("Binding payload and capabilities must be objects")
        allowed_capability_fields = {
            "idempotency_mode",
            "key_scope",
            "idempotency_retention_seconds",
            "rejects_payload_mismatch",
            "concurrent_deduplication",
            "supports_outcome_lookup",
        }
        if set(capabilities) != allowed_capability_fields:
            raise ValueError(
                "Binding capability metadata must contain the complete supported snapshot"
            )
        if capabilities.get("idempotency_mode") not in ("none", "provider_enforced"):
            raise ValueError("Binding idempotency mode is invalid")
        for name, value in capabilities.items():
            if name in {"rejects_payload_mismatch", "concurrent_deduplication", "supports_outcome_lookup"}:
                if not isinstance(value, bool):
                    raise ValueError(f"{name} capability must be a boolean")
            elif name == "idempotency_retention_seconds":
                if value is None and capabilities["idempotency_mode"] == "none":
                    continue
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise ValueError("Idempotency retention must be a positive integer")
            elif name == "key_scope":
                if value is None and capabilities["idempotency_mode"] == "none":
                    continue
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("key_scope capability must be a non-empty string")
            elif not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} capability must be a non-empty string")
        if capabilities["idempotency_mode"] == "provider_enforced":
            if (
                not capabilities.get("key_scope")
                or not capabilities.get("idempotency_retention_seconds")
                or capabilities.get("rejects_payload_mismatch") is not True
                or capabilities.get("concurrent_deduplication") is not True
            ):
                raise ValueError("Provider-enforced idempotency metadata is incomplete")
        elif any(
            capabilities.get(name) is True
            for name in ("rejects_payload_mismatch", "concurrent_deduplication")
        ) or capabilities.get("key_scope") is not None or capabilities.get("idempotency_retention_seconds") is not None:
            raise ValueError("Non-idempotent capability metadata cannot claim deduplication")

        payload_json = json.dumps(
            payload, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
        capabilities_json = json.dumps(
            capabilities, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
        now_text = _utc_now()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT r.tool_id, r.arguments_json, r.contract_fingerprint,
                       r.status, r.consumed_at, a.status AS attempt_status,
                       a.idempotency_key
                FROM tool_requests AS r
                LEFT JOIN tool_execution_attempts AS a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                WHERE r.id = ? AND r.user_id = ?
                """,
                (request_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("Claimed tool execution not found")
            if (
                row["status"] != "executing"
                or row["consumed_at"] is None
                or row["attempt_status"] != "claimed"
            ):
                raise PermissionError("Tool execution is not awaiting dispatch binding")
            if idempotency_key != request_id or row["idempotency_key"] != request_id:
                raise PermissionError("Dispatch binding idempotency key does not match request")
            if row["contract_fingerprint"] != tool_contract_fingerprint:
                raise PermissionError("Tool contract fingerprint does not match request")

            persisted_arguments = json.loads(row["arguments_json"])
            persisted_json = json.dumps(
                persisted_arguments, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            )
            if persisted_json != payload_json:
                raise PermissionError("Dispatch payload differs from authorized request")

            digest_input = {
                "user_id": user_id,
                "tool_id": row["tool_id"],
                "contract_fingerprint": tool_contract_fingerprint,
                "adapter_id": adapter_id,
                "adapter_version": adapter_version,
                "provider_id": provider_id,
                "provider_scope": provider_scope,
                "arguments": persisted_arguments,
            }
            expected_digest = hashlib.sha256(
                json.dumps(
                    digest_input, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            if action_digest != expected_digest:
                raise PermissionError("Dispatch action digest does not match authorized action")

            binding_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO tool_execution_bindings (
                    id, user_id, request_id, idempotency_key, action_digest,
                    payload_json, tool_contract_fingerprint, adapter_id,
                    adapter_version, provider_id, provider_scope,
                    capabilities_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    binding_id, user_id, request_id, idempotency_key,
                    action_digest, payload_json, tool_contract_fingerprint,
                    adapter_id, adapter_version, provider_id, provider_scope,
                    capabilities_json, now_text,
                ),
            )

        return self.get_execution_binding(user_id, request_id)

    def get_execution_binding(self, user_id: str, request_id: str) -> dict:
        row = self.database.connect().execute(
            """
            SELECT * FROM tool_execution_bindings
            WHERE request_id = ? AND user_id = ?
            """,
            (request_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Tool execution binding not found")
        result = dict(row)
        result["payload"] = json.loads(result.pop("payload_json"))
        result["capabilities"] = json.loads(result.pop("capabilities_json"))
        return result

    def claim_passkey_authorized_for_execution(
        self,
        user_id: str,
        request_id: str,
        *,
        expected_contract_fingerprint: str,
    ) -> dict:
        """Atomically claim a request backed by a matching, active passkey authorization."""
        if (
            not isinstance(expected_contract_fingerprint, str)
            or len(expected_contract_fingerprint) != 64
            or any(
                char not in "0123456789abcdef"
                for char in expected_contract_fingerprint
            )
        ):
            raise ValueError("Tool contract fingerprint is invalid")

        now = datetime.now(timezone.utc)
        now_text = now.isoformat()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT
                    r.*,
                    a.id AS authorization_id,
                    a.proposal_digest AS authorized_proposal_digest,
                    a.contract_fingerprint AS authorized_contract_fingerprint,
                    a.credential_id AS authorized_credential_id,
                    c.revoked_at AS credential_revoked_at,
                    h.purpose AS challenge_purpose,
                    h.request_id AS challenge_request_id,
                    h.proposal_digest AS challenge_proposal_digest,
                    h.contract_fingerprint AS challenge_contract_fingerprint,
                    h.consumed_at AS challenge_consumed_at,
                    u.deleted_at AS user_deleted_at
                FROM tool_requests AS r
                LEFT JOIN tool_authorizations AS a
                    ON a.request_id = r.id AND a.user_id = r.user_id
                LEFT JOIN webauthn_credentials AS c
                    ON c.id = a.credential_id AND c.user_id = a.user_id
                LEFT JOIN webauthn_challenges AS h
                    ON h.id = a.challenge_id AND h.user_id = a.user_id
                LEFT JOIN users AS u ON u.id = r.user_id
                WHERE r.id = ? AND r.user_id = ?
                """,
                (request_id, user_id),
            ).fetchone()

            if row is None:
                raise LookupError("Tool request not found")
            if row["authorization_policy"] != "passkey":
                raise PermissionError(
                    "Passkey execution is restricted to passkey-authorized requests"
                )
            if row["status"] != "approved" or row["consumed_at"] is not None:
                raise PermissionError("Tool request is not available for execution")
            if row["user_deleted_at"] is not None:
                raise PermissionError("User account is not active")
            if row["authorization_id"] is None or row["authorized_credential_id"] is None:
                raise PermissionError("A valid passkey authorization is required")
            if row["credential_revoked_at"] is not None:
                raise PermissionError("Authorizing passkey has been revoked")
            if (
                row["challenge_purpose"] != "tool_approval"
                or row["challenge_request_id"] != request_id
                or row["challenge_consumed_at"] is None
            ):
                raise PermissionError("Passkey authorization challenge is invalid")

            if (
                row["contract_fingerprint"] != expected_contract_fingerprint
                or row["authorized_contract_fingerprint"]
                != expected_contract_fingerprint
            ):
                raise PermissionError("Tool contract changed after authorization")

            expires_at = row["expires_at"]
            if not isinstance(expires_at, str) or not expires_at.strip():
                raise PermissionError("Tool request expiry is required")
            try:
                expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except (TypeError, ValueError) as exc:
                raise PermissionError("Tool request expiry is invalid") from exc
            if expiry.tzinfo is None or expiry.utcoffset() is None:
                raise PermissionError("Tool request expiry must include a timezone")
            if expiry <= now:
                raise PermissionError("Tool request has expired")

            try:
                arguments = json.loads(row["arguments_json"])
                audit = json.loads(row["audit_json"] or "{}")
                current_digest = _request_digest(
                    row["tool_id"],
                    arguments,
                    row["contract_fingerprint"],
                )
            except (TypeError, ValueError) as exc:
                raise PermissionError("Tool request proposal data is invalid") from exc

            proposal = audit.get("proposal") if isinstance(audit, dict) else None
            if (
                not isinstance(proposal, dict)
                or proposal.get("arguments_sha256") != current_digest
                or proposal.get("contract_fingerprint")
                != expected_contract_fingerprint
            ):
                raise PermissionError("Tool request proposal has changed")
            if (
                row["authorized_proposal_digest"] != current_digest
                or row["challenge_proposal_digest"] != current_digest
                or row["challenge_contract_fingerprint"]
                != expected_contract_fingerprint
            ):
                raise PermissionError("Passkey authorization does not match this proposal")

            claimed = connection.execute(
                """
                UPDATE tool_requests
                SET status = 'executing', consumed_at = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                  AND authorization_policy = 'passkey'
                  AND status = 'approved' AND consumed_at IS NULL
                """,
                (now_text, now_text, request_id, user_id),
            )
            if claimed.rowcount != 1:
                raise PermissionError("Tool request is not available for execution")

            # Persist the execution attempt in the same transaction as the claim.
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key,
                    status, claimed_at, updated_at
                ) VALUES (?, ?, ?, ?, 'claimed', ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    user_id,
                    request_id,
                    request_id,
                    now_text,
                    now_text,
                ),
            )

        return self.get(user_id, request_id)

    def get_execution_attempt(
        self,
        user_id: str,
        request_id: str,
    ) -> dict:
        row = self.database.connect().execute(
            """
            SELECT id, user_id, request_id, idempotency_key, status,
                   claimed_at, updated_at, finished_at, error_code
            FROM tool_execution_attempts
            WHERE user_id = ? AND request_id = ?
            """,
            (user_id, request_id),
        ).fetchone()
        if row is None:
            raise LookupError("Tool execution attempt not found")
        return dict(row)

    def complete_execution(
        self,
        user_id: str,
        request_id: str,
        *,
        result: dict,
    ) -> dict:
        validate_personal_payload(result)
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            cursor = connection.execute(
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

            attempt = connection.execute(
                """
                UPDATE tool_execution_attempts
                SET status = 'succeeded', updated_at = ?, finished_at = ?
                WHERE request_id = ? AND user_id = ? AND status = 'claimed'
                """,
                (now, now, request_id, user_id),
            )
            if attempt.rowcount != 1:
                raise PermissionError("Tool execution attempt is no longer active")
        return self.get(user_id, request_id)

    def fail_execution(
        self,
        user_id: str,
        request_id: str,
        *,
        error_code: str = "execution_failed",
    ) -> dict:
        if (
            not isinstance(error_code, str)
            or not error_code
            or len(error_code) > 64
            or not error_code.replace("_", "").isalnum()
        ):
            raise ValueError("Tool execution error code is invalid")

        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            cursor = connection.execute(
                "UPDATE tool_requests "
                "SET status = 'failed', updated_at = ? "
                "WHERE id = ? AND user_id = ? AND status = 'executing' "
                "AND consumed_at IS NOT NULL",
                (now, request_id, user_id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("Tool execution is no longer active")

            attempt = connection.execute(
                """
                UPDATE tool_execution_attempts
                SET status = 'failed', updated_at = ?, finished_at = ?,
                    error_code = ?
                WHERE request_id = ? AND user_id = ? AND status = 'claimed'
                """,
                (now, now, error_code, request_id, user_id),
            )
            if attempt.rowcount != 1:
                raise PermissionError("Tool execution attempt is no longer active")
        return self.get(user_id, request_id)

    def recover_stale_execution_attempts(self, *, stale_before: str) -> int:
        """Mark abandoned claims unknown; never retry an operation automatically."""
        try:
            cutoff = datetime.fromisoformat(stale_before.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("Stale-attempt cutoff must be a valid timestamp") from exc
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise ValueError("Stale-attempt cutoff must include a timezone")

        cutoff_text = cutoff.astimezone(timezone.utc).isoformat()
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            stale_rows = connection.execute(
                """
                SELECT request_id, user_id
                FROM tool_execution_attempts
                WHERE status = 'claimed' AND claimed_at < ?
                """,
                (cutoff_text,),
            ).fetchall()

            recovered = 0
            for row in stale_rows:
                attempt = connection.execute(
                    """
                    UPDATE tool_execution_attempts
                    SET status = 'outcome_unknown', updated_at = ?,
                        finished_at = ?, error_code = 'recovery_outcome_unknown'
                    WHERE request_id = ? AND user_id = ? AND status = 'claimed'
                    """,
                    (now, now, row["request_id"], row["user_id"]),
                )
                if attempt.rowcount != 1:
                    continue

                request_update = connection.execute(
                    """
                    UPDATE tool_requests
                    SET status = 'outcome_unknown', updated_at = ?
                    WHERE id = ? AND user_id = ? AND status = 'executing'
                      AND consumed_at IS NOT NULL
                    """,
                    (now, row["request_id"], row["user_id"]),
                )
                if request_update.rowcount != 1:
                    # Roll back the attempt transition as well. A recovered
                    # attempt and its owning request must never diverge.
                    raise PermissionError(
                        "Tool request is no longer awaiting recovery"
                    )
                recovered += 1
        return recovered

    def reconcile_execution_attempt(
        self,
        user_id: str,
        request_id: str,
        *,
        outcome: str,
        note: str,
        result: dict | None = None,
        error_code: str | None = None,
    ) -> dict:
        """Record an owner's manual resolution of an uncertain execution.

        This method never dispatches or retries the tool. The caller must have
        independently determined the external outcome before recording it.
        """
        if outcome not in ("succeeded", "failed"):
            raise ValueError("Reconciliation outcome must be succeeded or failed")
        if not isinstance(note, str) or not note.strip() or len(note) > 1000:
            raise ValueError("Reconciliation note must be 1 to 1000 characters")

        if outcome == "succeeded":
            if not isinstance(result, dict) or error_code is not None:
                raise ValueError(
                    "Successful reconciliation requires a result and no error code"
                )
            validate_personal_payload(result)
            result_json = json.dumps(result, ensure_ascii=False)
            final_status = "completed"
            final_error_code = None
        else:
            if result is not None:
                raise ValueError("Failed reconciliation cannot include a result")
            if error_code is None:
                error_code = "reconciled_failure"
            if (
                not isinstance(error_code, str)
                or not error_code
                or len(error_code) > 64
                or not error_code.replace("_", "").isalnum()
            ):
                raise ValueError("Tool execution error code is invalid")
            result_json = None
            final_status = "failed"
            final_error_code = error_code

        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT r.status AS request_status, r.consumed_at, r.audit_json,
                       a.status AS attempt_status
                FROM tool_requests AS r
                LEFT JOIN tool_execution_attempts AS a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                WHERE r.id = ? AND r.user_id = ?
                """,
                (request_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("Tool request not found")
            if (
                row["request_status"] != "outcome_unknown"
                or row["attempt_status"] != "outcome_unknown"
                or row["consumed_at"] is None
            ):
                raise PermissionError("Tool execution is not awaiting reconciliation")

            audit = json.loads(row["audit_json"] or "{}")
            if not isinstance(audit, dict):
                raise ValueError("Tool request audit data is invalid")
            if "execution_reconciliation" in audit:
                raise PermissionError("Tool execution has already been reconciled")

            audit["execution_reconciliation"] = {
                "outcome": outcome,
                "reconciled_by": user_id,
                "reconciled_at": now,
                "note": note.strip(),
            }
            request_update = connection.execute(
                """
                UPDATE tool_requests
                SET status = ?, result_json = ?, updated_at = ?, audit_json = ?
                WHERE id = ? AND user_id = ? AND status = 'outcome_unknown'
                  AND consumed_at IS NOT NULL
                """,
                (
                    final_status,
                    result_json,
                    now,
                    json.dumps(audit, ensure_ascii=False),
                    request_id,
                    user_id,
                ),
            )
            if request_update.rowcount != 1:
                raise PermissionError("Tool execution is no longer awaiting reconciliation")

            attempt_update = connection.execute(
                """
                UPDATE tool_execution_attempts
                SET status = ?, updated_at = ?, finished_at = ?, error_code = ?
                WHERE request_id = ? AND user_id = ? AND status = 'outcome_unknown'
                """,
                (
                    outcome,
                    now,
                    now,
                    final_error_code,
                    request_id,
                    user_id,
                ),
            )
            if attempt_update.rowcount != 1:
                raise PermissionError("Tool execution attempt is no longer awaiting reconciliation")

        return self.get(user_id, request_id)

    def cancel_pending(self, user_id: str, request_id: str) -> dict:
        """Cancel a pending or approved request before execution is claimed."""
        now = _utc_now()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                "UPDATE tool_requests SET status = 'cancelled', "
                "updated_at = ? "
                "WHERE id = ? AND user_id = ? "
                "AND status IN ('pending', 'approved') "
                "AND consumed_at IS NULL",
                (now, request_id, user_id),
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
