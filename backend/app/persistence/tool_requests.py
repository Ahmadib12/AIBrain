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

    def begin_external_dispatch(
        self,
        user_id: str,
        request_id: str,
        *,
        expected_contract_fingerprint: str,
        adapter_id: str,
        adapter_version: str,
        provider_id: str,
        provider_scope: str,
        capabilities: dict,
    ) -> dict:
        """Atomically revalidate a passkey authorization and freeze dispatch start."""
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT r.*, a.status AS attempt_status,
                       a.idempotency_key, a.id AS attempt_id,
                       z.id AS authorization_id, z.proposal_digest,
                       z.contract_fingerprint AS authorized_fingerprint,
                       z.credential_id, z.challenge_id,
                       c.revoked_at, h.purpose, h.request_id AS challenge_request_id,
                       h.consumed_at AS challenge_consumed_at,
                       h.proposal_digest AS challenge_digest,
                       h.contract_fingerprint AS challenge_fingerprint,
                       u.deleted_at
                FROM tool_requests AS r
                JOIN tool_execution_attempts AS a
                  ON a.request_id = r.id AND a.user_id = r.user_id
                LEFT JOIN tool_authorizations AS z
                  ON z.request_id = r.id AND z.user_id = r.user_id
                LEFT JOIN webauthn_credentials AS c
                  ON c.id = z.credential_id AND c.user_id = z.user_id
                LEFT JOIN webauthn_challenges AS h
                  ON h.id = z.challenge_id AND h.user_id = z.user_id
                JOIN users AS u ON u.id = r.user_id
                WHERE r.id = ? AND r.user_id = ?
                """,
                (request_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("External tool execution not found")
            if row["deleted_at"] is not None:
                raise PermissionError("User account is not active")
            if (
                row["authorization_policy"] != "passkey"
                or row["status"] != "executing"
                or row["consumed_at"] is None
                or row["attempt_status"] != "claimed"
                or row["idempotency_key"] != request_id
            ):
                raise PermissionError("Execution is not eligible for external dispatch")
            if (
                row["authorization_id"] is None
                or row["credential_id"] is None
                or row["revoked_at"] is not None
                or row["purpose"] != "tool_approval"
                or row["challenge_request_id"] != request_id
                or row["challenge_consumed_at"] is None
            ):
                raise PermissionError("Active passkey authorization is required")
            if (
                row["contract_fingerprint"] != expected_contract_fingerprint
                or row["authorized_fingerprint"] != expected_contract_fingerprint
                or row["challenge_fingerprint"] != expected_contract_fingerprint
            ):
                raise PermissionError("Authorized tool contract has changed")
            arguments = json.loads(row["arguments_json"])
            current_digest = _request_digest(
                row["tool_id"], arguments, expected_contract_fingerprint
            )
            audit = json.loads(row["audit_json"] or "{}")
            proposal = audit.get("proposal") if isinstance(audit, dict) else None
            if (
                not isinstance(proposal, dict)
                or proposal.get("arguments_sha256") != current_digest
                or row["proposal_digest"] != current_digest
                or row["challenge_digest"] != current_digest
            ):
                raise PermissionError("Passkey authorization does not match action")
            expires_at = row["expires_at"]
            if not isinstance(expires_at, str) or not expires_at.strip():
                raise PermissionError("Tool authorization expiry is required")
            try:
                expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise PermissionError("Tool authorization expiry is invalid") from exc
            if expiry.tzinfo is None or expiry.utcoffset() is None:
                raise PermissionError("Tool authorization expiry must include a timezone")
            if expiry <= datetime.now(timezone.utc):
                raise PermissionError("Tool authorization has expired")
            binding = connection.execute(
                """
                SELECT * FROM tool_execution_bindings
                WHERE request_id = ? AND user_id = ?
                """,
                (request_id, user_id),
            ).fetchone()
            if binding is None:
                raise PermissionError("Persisted external dispatch binding is required")
            if (
                binding["tool_contract_fingerprint"] != expected_contract_fingerprint
                or binding["adapter_id"] != adapter_id
                or binding["adapter_version"] != adapter_version
                or binding["provider_id"] != provider_id
                or binding["provider_scope"] != provider_scope
                or binding["capabilities_json"] != json.dumps(
                    capabilities, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False,
                )
                or json.loads(binding["payload_json"]) != arguments
            ):
                raise PermissionError("Registered adapter does not match dispatch binding")
            digest_input = {
                "user_id": user_id,
                "tool_id": row["tool_id"],
                "contract_fingerprint": expected_contract_fingerprint,
                "adapter_id": adapter_id,
                "adapter_version": adapter_version,
                "provider_id": provider_id,
                "provider_scope": provider_scope,
                "arguments": arguments,
            }
            digest = hashlib.sha256(json.dumps(
                digest_input, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")).hexdigest()
            if digest != binding["action_digest"]:
                raise PermissionError("Dispatch action digest verification failed")
            # Revalidate certification, attestation signature and key status
            # inside the same transaction that records dispatch_started.
            certification_rows = connection.execute(
                """
                SELECT c.* FROM external_adapter_certifications AS c
                WHERE c.provider_id = ? AND c.adapter_id = ?
                  AND c.adapter_version = ? AND c.provider_scope = ?
                  AND c.tool_id = ? AND c.tool_contract_fingerprint = ?
                  AND c.capabilities_json = ? AND c.expires_at > ?
                  AND NOT EXISTS (
                    SELECT 1 FROM external_adapter_certification_revocations AS cr
                    WHERE cr.certification_id = c.id
                  )
                ORDER BY c.created_at DESC, c.id DESC
                """,
                (
                    provider_id, adapter_id, adapter_version, provider_scope,
                    row["tool_id"], expected_contract_fingerprint,
                    json.dumps(capabilities, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False),
                    now,
                ),
            ).fetchall()
            trusted_certification = False
            for certification_row in certification_rows:
                try:
                    evidence_refs = json.loads(certification_row["evidence_references_json"])
                    package_id = evidence_refs[0].split(":", 1)[1]
                    package_row = connection.execute(
                        "SELECT * FROM external_adapter_evidence_packages WHERE id = ?",
                        (package_id,),
                    ).fetchone()
                    attestation_row = connection.execute(
                        """
                        SELECT a.*, k.public_key, k.valid_from, k.valid_until
                        FROM external_adapter_evidence_attestations AS a
                        JOIN trusted_runner_keys AS k ON k.key_id = a.key_id
                        WHERE a.package_id = ?
                          AND NOT EXISTS (
                            SELECT 1 FROM trusted_runner_key_revocations AS kr
                            WHERE kr.key_id = k.key_id
                          )
                        """,
                        (package_id,),
                    ).fetchone()
                    if package_row is None or attestation_row is None:
                        continue
                    attestation_payload = json.loads(attestation_row["payload_json"])
                    from backend.app.tools.attestation import (
                        _parse_timestamp, verify_package_attestation,
                    )
                    if (
                        _parse_timestamp(attestation_payload["expires_at"], "expires_at")
                        <= datetime.now(timezone.utc)
                        or _parse_timestamp(attestation_row["valid_from"], "valid_from")
                        > datetime.now(timezone.utc)
                        or _parse_timestamp(attestation_row["valid_until"], "valid_until")
                        <= datetime.now(timezone.utc)
                    ):
                        continue
                    signed_package = {
                        "id": package_id,
                        "manifest_sha256": package_row["manifest_sha256"],
                        "artifact_hashes": json.loads(package_row["artifact_hashes_json"]),
                        "provider_id": package_row["provider_id"],
                        "adapter_id": package_row["adapter_id"],
                        "adapter_version": package_row["adapter_version"],
                        "provider_scope": package_row["provider_scope"],
                        "sandbox_environment": package_row["sandbox_environment"],
                    }
                    if verify_package_attestation(
                        bytes(attestation_row["public_key"]),
                        attestation_payload, attestation_row["signature"],
                        package=signed_package, runner_id=attestation_row["runner_id"],
                    ) != attestation_row["payload_sha256"]:
                        continue
                    artifact_rows = connection.execute(
                        """
                        SELECT artifact_name, content
                        FROM external_adapter_evidence_artifacts
                        WHERE package_id = ?
                        """,
                        (package_id,),
                    ).fetchall()
                    from backend.app.tools.conformance import verify_evidence_manifest
                    evidence_check = verify_evidence_manifest(
                        json.loads(package_row["manifest_json"]),
                        {item["artifact_name"]: bytes(item["content"])
                         for item in artifact_rows},
                    )
                    if (
                        evidence_check["manifest_sha256"] != package_row["manifest_sha256"]
                        or evidence_check["artifact_sha256"]
                           != json.loads(package_row["artifact_hashes_json"])
                        or attestation_payload["package_id"] != package_id
                        or attestation_payload["manifest_sha256"] != package_row["manifest_sha256"]
                        or package_row["provider_id"] != provider_id
                        or package_row["adapter_id"] != adapter_id
                        or package_row["adapter_version"] != adapter_version
                        or package_row["provider_scope"] != provider_scope
                        or package_row["tool_id"] != row["tool_id"]
                        or package_row["tool_contract_fingerprint"] != expected_contract_fingerprint
                        or package_row["capabilities_json"] != json.dumps(
                            capabilities, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"), allow_nan=False,
                        )
                    ):
                        continue
                    trusted_certification = True
                    break
                except (
                    IndexError, KeyError, LookupError, TypeError, ValueError,
                    PermissionError,
                ):
                    continue
            if not trusted_certification:
                raise PermissionError(
                    "Active trusted evidence certification is required at dispatch time"
                )

            existing = connection.execute(
                """
                SELECT 1 FROM tool_dispatch_audit_events
                WHERE request_id = ? AND event_type = 'dispatch_started'
                """,
                (request_id,),
            ).fetchone()
            if existing is not None:
                raise PermissionError("External dispatch has already been initiated")
            connection.execute(
                """
                INSERT INTO tool_dispatch_audit_events
                    (id, user_id, request_id, event_type, action_digest,
                     details_json, created_at)
                VALUES (?, ?, ?, 'dispatch_started', ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), user_id, request_id, digest,
                    json.dumps({
                        "attempt_id": row["attempt_id"],
                        "adapter_id": adapter_id,
                        "adapter_version": adapter_version,
                        "provider_id": provider_id,
                        "provider_scope": provider_scope,
                    }, sort_keys=True, separators=(",", ":")),
                    now,
                ),
            )
        return {
            "request_id": request_id,
            "idempotency_key": row["idempotency_key"],
            "action_digest": digest,
            "payload": arguments,
        }

    def record_external_dispatch_outcome(
        self,
        user_id: str,
        request_id: str,
        *,
        outcome: str,
        action_digest: str,
        result: dict | None = None,
        error_code: str | None = None,
        evidence_reference: str | None = None,
    ) -> dict:
        """Persist one definitive or unknown provider outcome without retrying."""
        if outcome not in ("succeeded", "failed", "unknown"):
            raise ValueError("External dispatch outcome is invalid")
        if not isinstance(action_digest, str) or len(action_digest) != 64:
            raise ValueError("Action digest is invalid")
        if outcome == "succeeded":
            if not isinstance(result, dict) or error_code is not None:
                raise ValueError("Successful outcome requires a result only")
            validate_personal_payload(result)
        else:
            if result is not None:
                raise ValueError("Non-success outcome cannot contain a result")
            if (
                not isinstance(error_code, str)
                or not error_code
                or len(error_code) > 64
                or not error_code.replace("_", "").isalnum()
            ):
                raise ValueError("External dispatch error code is invalid")
        if evidence_reference is not None and (
            not isinstance(evidence_reference, str)
            or not evidence_reference.strip()
            or len(evidence_reference) > 256
        ):
            raise ValueError("Provider evidence reference is invalid")
        now = _utc_now()
        request_status = {
            "succeeded": "completed",
            "failed": "failed",
            "unknown": "outcome_unknown",
        }[outcome]
        attempt_status = {
            "succeeded": "succeeded",
            "failed": "failed",
            "unknown": "outcome_unknown",
        }[outcome]
        event_type = {
            "succeeded": "dispatch_succeeded",
            "failed": "dispatch_failed",
            "unknown": "dispatch_unknown",
        }[outcome]
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            started = connection.execute(
                """
                SELECT action_digest FROM tool_dispatch_audit_events
                WHERE request_id = ? AND user_id = ?
                  AND event_type = 'dispatch_started'
                """,
                (request_id, user_id),
            ).fetchone()
            if started is None or started["action_digest"] != action_digest:
                raise PermissionError("No matching initiated dispatch exists")
            prior = connection.execute(
                """
                SELECT 1 FROM tool_dispatch_audit_events
                WHERE request_id = ? AND user_id = ?
                  AND event_type IN (
                    'dispatch_succeeded', 'dispatch_failed', 'dispatch_unknown'
                  )
                """,
                (request_id, user_id),
            ).fetchone()
            if prior is not None:
                raise PermissionError("Dispatch outcome has already been recorded")
            connection.execute(
                """
                INSERT INTO tool_dispatch_audit_events
                    (id, user_id, request_id, event_type, action_digest,
                     details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), user_id, request_id, event_type,
                    action_digest,
                    json.dumps({
                        "error_code": error_code,
                        "evidence_reference": evidence_reference,
                    }, sort_keys=True, separators=(",", ":")),
                    now,
                ),
            )
            request_update = connection.execute(
                """
                UPDATE tool_requests
                SET status = ?, result_json = ?, updated_at = ?
                WHERE id = ? AND user_id = ? AND status = 'executing'
                  AND consumed_at IS NOT NULL
                """,
                (
                    request_status,
                    json.dumps(result, ensure_ascii=False) if result is not None else None,
                    now, request_id, user_id,
                ),
            )
            if request_update.rowcount != 1:
                raise PermissionError("Tool request is no longer dispatchable")
            attempt_update = connection.execute(
                """
                UPDATE tool_execution_attempts
                SET status = ?, updated_at = ?, finished_at = ?, error_code = ?
                WHERE request_id = ? AND user_id = ? AND status = 'claimed'
                """,
                (attempt_status, now, now, error_code, request_id, user_id),
            )
            if attempt_update.rowcount != 1:
                raise PermissionError("Tool execution attempt is no longer active")
        return self.get(user_id, request_id)

    def record_external_outcome_lookup(
        self,
        user_id: str,
        request_id: str,
        *,
        action_digest: str,
        outcome: str,
        evidence_reference: str | None,
    ) -> None:
        if outcome not in ("succeeded", "failed", "unknown"):
            raise ValueError("Lookup outcome is invalid")
        if evidence_reference is not None and (
            not isinstance(evidence_reference, str)
            or not evidence_reference.strip()
            or len(evidence_reference) > 256
        ):
            raise ValueError("Provider evidence reference is invalid")
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            started = connection.execute(
                """
                SELECT action_digest FROM tool_dispatch_audit_events
                WHERE user_id = ? AND request_id = ?
                  AND event_type = 'dispatch_started'
                """,
                (user_id, request_id),
            ).fetchone()
            if started is None or started["action_digest"] != action_digest:
                raise PermissionError("No matching dispatch exists for lookup")
            connection.execute(
                """
                INSERT INTO tool_dispatch_audit_events
                    (id, user_id, request_id, event_type, action_digest,
                     details_json, created_at)
                VALUES (?, ?, ?, 'outcome_lookup', ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()), user_id, request_id, action_digest,
                    json.dumps({
                        "observed_outcome": outcome,
                        "evidence_reference": evidence_reference,
                    }, sort_keys=True, separators=(",", ":")),
                    now,
                ),
            )

    def get_dispatch_audit(self, user_id: str, request_id: str) -> list[dict]:
        rows = self.database.connect().execute(
            """
            SELECT event_type, action_digest, details_json, created_at
            FROM tool_dispatch_audit_events
            WHERE user_id = ? AND request_id = ?
            ORDER BY created_at, id
            """,
            (user_id, request_id),
        ).fetchall()
        return [
            {
                "event_type": row["event_type"],
                "action_digest": row["action_digest"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

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

    def verify_external_adapter_evidence(
        self,
        manifest: dict,
        artifacts: dict[str, bytes],
    ) -> dict:
        """Verify and immutably persist evidence bytes before any human approval."""
        from backend.app.tools.conformance import verify_evidence_manifest

        verified = verify_evidence_manifest(manifest, artifacts)
        package_id = str(uuid.uuid4())
        normalized = verified["manifest"]
        now = verified["verified_at"]
        capabilities_json = json.dumps(
            normalized["capabilities"], ensure_ascii=False,
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            connection.execute(
                """
                INSERT INTO external_adapter_evidence_packages (
                    id, provider_id, adapter_id, adapter_version, provider_scope,
                    tool_id, tool_contract_fingerprint, capabilities_json,
                    test_suite_version, sandbox_environment, manifest_json,
                    manifest_sha256, artifact_hashes_json,
                    conformance_results_json, executed_at, verified_at,
                    expires_at, provenance, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unattested', ?)
                """,
                (
                    package_id, normalized["provider_id"], normalized["adapter_id"],
                    normalized["adapter_version"], normalized["provider_scope"],
                    normalized["tool_id"], normalized["tool_contract_fingerprint"],
                    capabilities_json, normalized["test_suite_version"],
                    normalized["sandbox_environment"],
                    json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False),
                    verified["manifest_sha256"],
                    json.dumps(verified["artifact_sha256"], sort_keys=True,
                               separators=(",", ":")),
                    json.dumps(verified["conformance_results"], sort_keys=True,
                               separators=(",", ":")),
                    normalized["executed_at"], now, verified["expires_at"], now,
                ),
            )
            for name, content in artifacts.items():
                connection.execute(
                    """
                    INSERT INTO external_adapter_evidence_artifacts
                        (id, package_id, artifact_name, sha256, content)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (str(uuid.uuid4()), package_id, name,
                     verified["artifact_sha256"][name], content),
                )
        return self.get_external_adapter_evidence_package(package_id)

    def get_external_adapter_evidence_package(self, package_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM external_adapter_evidence_packages WHERE id = ?",
            (package_id,),
        ).fetchone()
        if row is None:
            raise LookupError("Verified evidence package not found")
        artifacts = self.database.connect().execute(
            """
            SELECT artifact_name, sha256, content
            FROM external_adapter_evidence_artifacts
            WHERE package_id = ? ORDER BY artifact_name
            """,
            (package_id,),
        ).fetchall()
        attestation_state = self.database.connect().execute(
            """
            SELECT EXISTS(
                SELECT 1 FROM external_adapter_evidence_attestations AS a
                WHERE a.package_id = ?
            ) AS attested,
            EXISTS(
                SELECT 1 FROM external_adapter_evidence_attestations AS a
                JOIN trusted_runner_key_revocations AS r ON r.key_id = a.key_id
                WHERE a.package_id = ?
            ) AS revoked
            """,
            (package_id, package_id),
        ).fetchone()
        provenance = (
            "runner_attestation_revoked" if attestation_state["revoked"]
            else "runner_attested" if attestation_state["attested"]
            else row["provenance"]
        )
        return {
            "id": row["id"],
            "provider_id": row["provider_id"],
            "adapter_id": row["adapter_id"],
            "adapter_version": row["adapter_version"],
            "provider_scope": row["provider_scope"],
            "tool_id": row["tool_id"],
            "tool_contract_fingerprint": row["tool_contract_fingerprint"],
            "capabilities": json.loads(row["capabilities_json"]),
            "test_suite_version": row["test_suite_version"],
            "sandbox_environment": row["sandbox_environment"],
            "manifest": json.loads(row["manifest_json"]),
            "manifest_sha256": row["manifest_sha256"],
            "artifact_hashes": json.loads(row["artifact_hashes_json"]),
            "conformance_results": json.loads(row["conformance_results_json"]),
            "artifacts": {
                item["artifact_name"]: {
                    "sha256": item["sha256"], "content": bytes(item["content"])
                } for item in artifacts
            },
            "executed_at": row["executed_at"],
            "verified_at": row["verified_at"],
            "expires_at": row["expires_at"],
            "provenance": provenance,
        }

    def register_trusted_runner_key(
        self, *, key_id: str, runner_id: str, public_key: bytes,
        valid_from: str, valid_until: str, registered_by: str,
    ) -> dict:
        """Register an externally generated Ed25519 public key; never stores private keys."""
        from backend.app.tools.attestation import _parse_timestamp

        for field, value in (
            ("key_id", key_id), ("runner_id", runner_id),
            ("registered_by", registered_by),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{field} must be a non-empty bounded identifier")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("Ed25519 public key must contain exactly 32 bytes")
        start = _parse_timestamp(valid_from, "valid_from")
        end = _parse_timestamp(valid_until, "valid_until")
        now = datetime.now(timezone.utc)
        if end <= start or end <= now:
            raise ValueError("Trusted runner key validity window is invalid or expired")
        with self.database.transaction(immediate=True):
            self.database.connect().execute(
                """
                INSERT INTO trusted_runner_keys (
                    key_id, runner_id, algorithm, public_key,
                    valid_from, valid_until, registered_by, created_at
                ) VALUES (?, ?, 'Ed25519', ?, ?, ?, ?, ?)
                """,
                (key_id, runner_id, public_key, start.isoformat(),
                 end.isoformat(), registered_by.strip(), now.isoformat()),
            )
        return self.get_trusted_runner_key(key_id)

    def get_trusted_runner_key(self, key_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM trusted_runner_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Trusted runner key not found")
        revoked = self.database.connect().execute(
            "SELECT revoked_by, reason, created_at FROM trusted_runner_key_revocations "
            "WHERE key_id = ? ORDER BY created_at DESC LIMIT 1", (key_id,)
        ).fetchone()
        return {
            "key_id": row["key_id"], "runner_id": row["runner_id"],
            "algorithm": row["algorithm"], "public_key": bytes(row["public_key"]),
            "valid_from": row["valid_from"], "valid_until": row["valid_until"],
            "registered_by": row["registered_by"], "created_at": row["created_at"],
            "revocation": dict(revoked) if revoked else None,
        }

    def revoke_trusted_runner_key(
        self, key_id: str, *, revoked_by: str, reason: str
    ) -> None:
        if not isinstance(revoked_by, str) or not revoked_by.strip():
            raise ValueError("Revoking operator must be identified")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise ValueError("Key revocation reason must be 1 to 1000 characters")
        with self.database.transaction(immediate=True):
            exists = self.database.connect().execute(
                "SELECT 1 FROM trusted_runner_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
            if exists is None:
                raise LookupError("Trusted runner key not found")
            prior = self.database.connect().execute(
                "SELECT 1 FROM trusted_runner_key_revocations WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if prior:
                raise PermissionError("Trusted runner key is already revoked")
            self.database.connect().execute(
                """
                INSERT INTO trusted_runner_key_revocations
                    (id, key_id, revoked_by, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), key_id, revoked_by.strip(),
                 reason.strip(), _utc_now()),
            )

    def attest_external_adapter_evidence(
        self, package_id: str, *, key_id: str, runner_id: str,
        nonce: str, issued_at: str, expires_at: str, signature: str,
    ) -> dict:
        """Verify trusted-runner signature and atomically consume its nonce."""
        from backend.app.tools.attestation import (
            _parse_timestamp, build_attestation_payload,
            verify_ed25519_signature,
        )
        from backend.app.tools.conformance import verify_evidence_manifest

        package = self.get_external_adapter_evidence_package(package_id)
        key = self.get_trusted_runner_key(key_id)
        now = datetime.now(timezone.utc)
        if key["revocation"] is not None:
            raise PermissionError("Trusted runner key has been revoked")
        key_start = _parse_timestamp(key["valid_from"], "valid_from")
        key_end = _parse_timestamp(key["valid_until"], "valid_until")
        issued = _parse_timestamp(issued_at, "issued_at")
        expiry = _parse_timestamp(expires_at, "expires_at")
        if not (key_start <= issued <= now < expiry <= key_end):
            raise PermissionError("Attestation is outside the trusted key validity window")
        if expiry > _parse_timestamp(package["expires_at"], "package_expires_at"):
            raise PermissionError("Attestation cannot outlive its evidence package")
        if issued < _parse_timestamp(package["executed_at"], "executed_at"):
            raise PermissionError("Attestation predates the evidence execution")
        verified = verify_evidence_manifest(
            package["manifest"],
            {name: item["content"] for name, item in package["artifacts"].items()},
        )
        if (
            verified["manifest_sha256"] != package["manifest_sha256"]
            or verified["artifact_sha256"] != package["artifact_hashes"]
        ):
            raise PermissionError("Evidence package integrity verification failed")
        if runner_id != key["runner_id"]:
            raise PermissionError("Attestation runner does not match trusted key")
        payload = build_attestation_payload(
            package_id=package_id,
            manifest_sha256=package["manifest_sha256"],
            artifact_hashes=package["artifact_hashes"],
            runner_id=runner_id,
            provider_id=package["provider_id"],
            adapter_id=package["adapter_id"],
            adapter_version=package["adapter_version"],
            provider_scope=package["provider_scope"],
            sandbox_environment=package["sandbox_environment"],
            nonce=nonce, issued_at=issued_at, expires_at=expires_at,
        )
        payload_hash = verify_ed25519_signature(
            key["public_key"], payload, signature
        )
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            if connection.execute(
                "SELECT 1 FROM trusted_runner_key_revocations WHERE key_id = ?",
                (key_id,),
            ).fetchone():
                raise PermissionError("Trusted runner key was revoked during verification")
            if connection.execute(
                "SELECT 1 FROM external_adapter_evidence_attestations WHERE package_id = ?",
                (package_id,),
            ).fetchone():
                raise PermissionError("Evidence package already has a runner attestation")
            if connection.execute(
                "SELECT 1 FROM external_adapter_evidence_attestations WHERE nonce = ?",
                (nonce,),
            ).fetchone():
                raise PermissionError("Attestation nonce has already been used")
            connection.execute(
                """
                INSERT INTO external_adapter_evidence_attestations (
                    id, package_id, key_id, runner_id, nonce,
                    payload_json, payload_sha256, signature, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), package_id, key_id, runner_id, nonce,
                 json.dumps(payload, sort_keys=True, separators=(",", ":")),
                 payload_hash, signature, now.isoformat()),
            )
        return self.get_external_adapter_evidence_attestation(package_id)

    def get_external_adapter_evidence_attestation(self, package_id: str) -> dict:
        row = self.database.connect().execute(
            """
            SELECT a.*, k.valid_from, k.valid_until,
                   EXISTS(
                     SELECT 1 FROM trusted_runner_key_revocations AS r
                     WHERE r.key_id = k.key_id
                   ) AS key_revoked
            FROM external_adapter_evidence_attestations AS a
            JOIN trusted_runner_keys AS k ON k.key_id = a.key_id
            WHERE a.package_id = ?
            """, (package_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Trusted runner attestation not found")
        return {
            "id": row["id"], "package_id": row["package_id"],
            "key_id": row["key_id"], "runner_id": row["runner_id"],
            "nonce": row["nonce"], "payload": json.loads(row["payload_json"]),
            "payload_sha256": row["payload_sha256"],
            "signature": row["signature"], "verified_at": row["verified_at"],
            "key_valid_from": row["valid_from"], "key_valid_until": row["valid_until"],
            "key_revoked": bool(row["key_revoked"]),
        }

    def certify_external_adapter(
        self,
        *,
        evidence_package_id: str,
        approved_by: str,
        expires_at: str,
    ) -> dict:
        """Human approval of a previously verified, exact-scope evidence package."""
        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ValueError("Approving operator must be identified")
        package = self.get_external_adapter_evidence_package(evidence_package_id)
        try:
            attestation = self.get_external_adapter_evidence_attestation(evidence_package_id)
        except LookupError as exc:
            raise PermissionError("Trusted runner attestation is required for certification") from exc
        if attestation["key_revoked"]:
            raise PermissionError("Evidence signer key has been revoked")
        attestation_expiry = datetime.fromisoformat(
            attestation["payload"]["expires_at"].replace("Z", "+00:00")
        )
        if attestation_expiry.tzinfo is None or attestation_expiry <= datetime.now(timezone.utc):
            raise PermissionError("Runner attestation has expired")
        from backend.app.tools.conformance import verify_evidence_manifest

        reverified = verify_evidence_manifest(
            package["manifest"],
            {name: item["content"] for name, item in package["artifacts"].items()},
        )
        if (
            reverified["manifest_sha256"] != package["manifest_sha256"]
            or reverified["artifact_sha256"] != package["artifact_hashes"]
            or package["expires_at"] <= _utc_now()
        ):
            raise PermissionError("Evidence package integrity or freshness check failed")
        try:
            expiry = datetime.fromisoformat(expires_at)
        except (TypeError, ValueError) as exc:
            raise ValueError("Certification expiry must be an ISO timestamp") from exc
        now = datetime.now(timezone.utc)
        if expiry.tzinfo is None or expiry <= now:
            raise ValueError("Certification expiry must be timezone-aware and in the future")
        if expiry > datetime.fromisoformat(package["expires_at"]):
            raise ValueError("Certification cannot outlive its evidence package")
        if expiry > attestation_expiry:
            raise ValueError("Certification cannot outlive its runner attestation")

        certification_id = str(uuid.uuid4())
        now_text = now.isoformat()
        with self.database.transaction(immediate=True):
            current_attestation = self.database.connect().execute(
                """
                SELECT a.key_id FROM external_adapter_evidence_attestations AS a
                WHERE a.package_id = ?
                  AND NOT EXISTS (
                    SELECT 1 FROM trusted_runner_key_revocations AS r
                    WHERE r.key_id = a.key_id
                  )
                """,
                (evidence_package_id,),
            ).fetchone()
            if current_attestation is None:
                raise PermissionError("Trusted runner key is revoked or attestation is missing")
            self.database.connect().execute(
                """
                INSERT INTO external_adapter_certifications (
                    id, provider_id, adapter_id, adapter_version, provider_scope,
                    tool_id, tool_contract_fingerprint, capabilities_json,
                    test_suite_version, conformance_results_json,
                    test_report_sha256, evidence_references_json, verified_at,
                    expires_at, approved_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    certification_id, package["provider_id"], package["adapter_id"],
                    package["adapter_version"], package["provider_scope"],
                    package["tool_id"], package["tool_contract_fingerprint"],
                    json.dumps(package["capabilities"], sort_keys=True, separators=(",", ":")),
                    package["test_suite_version"],
                    json.dumps(package["conformance_results"], sort_keys=True, separators=(",", ":")),
                    package["manifest_sha256"],
                    json.dumps([f"evidence-package:{evidence_package_id}"]),
                    package["verified_at"], expiry.astimezone(timezone.utc).isoformat(), approved_by.strip(),
                    now_text,
                ),
            )
        return self.get_external_adapter_certification(certification_id)

    def get_external_adapter_certification(self, certification_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM external_adapter_certifications WHERE id = ?",
            (certification_id,),
        ).fetchone()
        if row is None:
            raise LookupError("Adapter certification not found")
        return {
            "id": row["id"],
            "provider_id": row["provider_id"],
            "adapter_id": row["adapter_id"],
            "adapter_version": row["adapter_version"],
            "provider_scope": row["provider_scope"],
            "tool_id": row["tool_id"],
            "tool_contract_fingerprint": row["tool_contract_fingerprint"],
            "capabilities": json.loads(row["capabilities_json"]),
            "test_suite_version": row["test_suite_version"],
            "conformance_results": json.loads(row["conformance_results_json"]),
            "test_report_sha256": row["test_report_sha256"],
            "evidence_references": json.loads(row["evidence_references_json"]),
            "verified_at": row["verified_at"],
            "expires_at": row["expires_at"],
            "approved_by": row["approved_by"],
            "created_at": row["created_at"],
        }

    def get_active_external_adapter_certification(
        self,
        *,
        provider_id: str,
        adapter_id: str,
        adapter_version: str,
        provider_scope: str,
        tool_id: str,
        tool_contract_fingerprint: str,
        capabilities: dict,
    ) -> dict | None:
        now = datetime.now(timezone.utc).isoformat()
        rows = self.database.connect().execute(
            """
            SELECT c.*
            FROM external_adapter_certifications AS c
            WHERE c.provider_id = ? AND c.adapter_id = ?
              AND c.adapter_version = ? AND c.provider_scope = ?
              AND c.tool_id = ? AND c.tool_contract_fingerprint = ?
              AND c.expires_at > ?
              AND NOT EXISTS (
                SELECT 1 FROM external_adapter_certification_revocations AS r
                WHERE r.certification_id = c.id
              )
            ORDER BY c.created_at DESC, c.id DESC
            """,
            (
                provider_id, adapter_id, adapter_version, provider_scope,
                tool_id, tool_contract_fingerprint, now,
            ),
        ).fetchall()
        expected = json.dumps(
            capabilities, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
        for row in rows:
            if row["capabilities_json"] != expected:
                continue
            certification = self.get_external_adapter_certification(row["id"])
            try:
                package_id = certification["evidence_references"][0].split(":", 1)[1]
                package = self.get_external_adapter_evidence_package(package_id)
                attestation = self.get_external_adapter_evidence_attestation(package_id)
                from backend.app.tools.attestation import (
                    verify_package_attestation,
                )
                from backend.app.tools.conformance import verify_evidence_manifest

                if attestation["key_revoked"]:
                    continue
                from backend.app.tools.attestation import _parse_timestamp
                if (
                    _parse_timestamp(attestation["payload"]["expires_at"], "expires_at")
                    <= datetime.now(timezone.utc)
                ):
                    continue
                key = self.get_trusted_runner_key(attestation["key_id"])
                if verify_package_attestation(
                    key["public_key"], attestation["payload"],
                    attestation["signature"], package=package,
                    runner_id=attestation["runner_id"],
                ) != attestation["payload_sha256"]:
                    continue
                verified = verify_evidence_manifest(
                    package["manifest"],
                    {name: item["content"] for name, item in package["artifacts"].items()},
                )
            except (IndexError, KeyError, LookupError, TypeError, ValueError, PermissionError):
                continue
            if (
                verified["manifest_sha256"] != certification["test_report_sha256"]
                or verified["manifest_sha256"] != package["manifest_sha256"]
                or verified["artifact_sha256"] != package["artifact_hashes"]
                or package["expires_at"] <= now
                or package["provider_id"] != provider_id
                or package["adapter_id"] != adapter_id
                or package["adapter_version"] != adapter_version
                or package["provider_scope"] != provider_scope
                or package["tool_id"] != tool_id
                or package["tool_contract_fingerprint"] != tool_contract_fingerprint
                or package["capabilities"] != capabilities
            ):
                continue
            return certification
        return None

    def revoke_external_adapter_certification(
        self, certification_id: str, *, revoked_by: str, reason: str
    ) -> None:
        if not isinstance(revoked_by, str) or not revoked_by.strip():
            raise ValueError("Revoking operator must be identified")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise ValueError("Revocation reason must be 1 to 1000 characters")
        with self.database.transaction(immediate=True):
            exists = self.database.connect().execute(
                "SELECT 1 FROM external_adapter_certifications WHERE id = ?",
                (certification_id,),
            ).fetchone()
            if exists is None:
                raise LookupError("Adapter certification not found")
            already = self.database.connect().execute(
                "SELECT 1 FROM external_adapter_certification_revocations "
                "WHERE certification_id = ?",
                (certification_id,),
            ).fetchone()
            if already is not None:
                raise PermissionError("Adapter certification is already revoked")
            self.database.connect().execute(
                """
                INSERT INTO external_adapter_certification_revocations
                    (id, certification_id, revoked_by, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), certification_id, revoked_by, reason.strip(),
                 _utc_now()),
            )

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
