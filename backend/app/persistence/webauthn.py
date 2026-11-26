import json
import sqlite3
import uuid
from datetime import datetime, timezone


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WebAuthnRepository:
    """Persistence operations for registered WebAuthn credentials."""

    _ALLOWED_TRANSPORTS = {
        "usb",
        "nfc",
        "ble",
        "internal",
        "hybrid",
        "cable",
        "smart-card",
    }

    _ALLOWED_DEVICE_TYPES = {
        "single_device",
        "multi_device",
    }

    def __init__(self, database):
        self.database = database

    @staticmethod
    def _credential_from_row(row):
        if row is None:
            return None

        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "credential_id": row["credential_id"],
            "public_key": bytes(row["public_key"]),
            "sign_count": row["sign_count"],
            "transports": json.loads(row["transports_json"]),
            "device_type": row["device_type"],
            "backed_up": bool(row["backed_up"]),
            "name": row["name"],
            "created_at": row["created_at"],
            "last_used_at": row["last_used_at"],
            "revoked_at": row["revoked_at"],
        }

    @staticmethod
    def _validate_user_id(user_id):
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")

    @staticmethod
    def _validate_credential_id(credential_id):
        if (
            not isinstance(credential_id, str)
            or not credential_id.strip()
        ):
            raise ValueError("credential_id must be a non-empty string")

    @staticmethod
    def _validate_public_key(public_key):
        if not isinstance(public_key, (bytes, bytearray, memoryview)):
            raise ValueError("public_key must be bytes-like")

        if not public_key:
            raise ValueError("public_key must not be empty")

        return bytes(public_key)

    @staticmethod
    def _validate_sign_count(sign_count):
        if (
            isinstance(sign_count, bool)
            or not isinstance(sign_count, int)
            or sign_count < 0
        ):
            raise ValueError("sign_count must be a non-negative integer")

    def _require_active_user(self, connection, user_id):
        row = connection.execute(
            """
            SELECT id
            FROM users
            WHERE id = ? AND deleted_at IS NULL
            """,
            (user_id,),
        ).fetchone()

        if row is None:
            raise LookupError("Active user account not found")

    def create_credential(
        self,
        *,
        user_id,
        credential_id,
        public_key,
        sign_count=0,
        transports=(),
        device_type=None,
        backed_up=False,
        name=None,
    ):
        self._validate_user_id(user_id)
        self._validate_credential_id(credential_id)
        public_key = self._validate_public_key(public_key)
        self._validate_sign_count(sign_count)

        if isinstance(transports, (str, bytes)):
            raise ValueError("transports must be a collection of strings")

        try:
            transports = list(transports)
        except TypeError as exc:
            raise ValueError(
                "transports must be a collection of strings"
            ) from exc

        if any(
            not isinstance(item, str)
            or item not in self._ALLOWED_TRANSPORTS
            for item in transports
        ):
            raise ValueError("transports contains an unsupported value")

        transports = list(dict.fromkeys(transports))

        if device_type is not None and device_type not in self._ALLOWED_DEVICE_TYPES:
            raise ValueError("Unsupported WebAuthn device_type")

        if not isinstance(backed_up, bool):
            raise ValueError("backed_up must be a boolean")

        if name is not None:
            if not isinstance(name, str) or not name.strip():
                raise ValueError("name must be a non-empty string or None")
            if len(name) > 128:
                raise ValueError("name must not exceed 128 characters")
            name = name.strip()

        credential_record_id = str(uuid.uuid4())
        created_at = _utc_now()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            self._require_active_user(connection, user_id)

            connection.execute(
                """
                INSERT INTO webauthn_credentials (
                    id,
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    transports_json,
                    device_type,
                    backed_up,
                    name,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    credential_record_id,
                    user_id,
                    credential_id,
                    sqlite3.Binary(public_key),
                    sign_count,
                    json.dumps(transports),
                    device_type,
                    int(backed_up),
                    name,
                    created_at,
                ),
            )

            row = connection.execute(
                """
                SELECT *
                FROM webauthn_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_record_id, user_id),
            ).fetchone()

        return self._credential_from_row(row)

    def get_credential(self, user_id, credential_record_id):
        self._validate_user_id(user_id)

        if (
            not isinstance(credential_record_id, str)
            or not credential_record_id.strip()
        ):
            raise ValueError(
                "credential_record_id must be a non-empty string"
            )

        row = self.database.connect().execute(
            """
            SELECT *
            FROM webauthn_credentials
            WHERE id = ? AND user_id = ?
            """,
            (credential_record_id, user_id),
        ).fetchone()

        return self._credential_from_row(row)

    def get_credential_by_credential_id(self, user_id, credential_id):
        """Resolve a browser credential ID within one account."""
        self._validate_user_id(user_id)
        self._validate_credential_id(credential_id)

        row = self.database.connect().execute(
            """
            SELECT *
            FROM webauthn_credentials
            WHERE user_id = ? AND credential_id = ?
            """,
            (user_id, credential_id),
        ).fetchone()

        return self._credential_from_row(row)

    def list_credentials(self, user_id, *, include_revoked=False):
        self._validate_user_id(user_id)

        if not isinstance(include_revoked, bool):
            raise ValueError("include_revoked must be a boolean")

        query = """
            SELECT *
            FROM webauthn_credentials
            WHERE user_id = ?
        """

        if not include_revoked:
            query += " AND revoked_at IS NULL"

        query += " ORDER BY created_at, id"

        rows = self.database.connect().execute(
            query,
            (user_id,),
        ).fetchall()

        return [
            self._credential_from_row(row)
            for row in rows
        ]

    def revoke_credential(self, user_id, credential_record_id):
        self._validate_user_id(user_id)

        if (
            not isinstance(credential_record_id, str)
            or not credential_record_id.strip()
        ):
            raise ValueError(
                "credential_record_id must be a non-empty string"
            )

        revoked_at = _utc_now()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()

            row = connection.execute(
                """
                SELECT *
                FROM webauthn_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_record_id, user_id),
            ).fetchone()

            if row is None:
                raise LookupError("Credential not found")

            if row["revoked_at"] is None:
                connection.execute(
                    """
                    UPDATE webauthn_credentials
                    SET revoked_at = ?
                    WHERE id = ? AND user_id = ?
                      AND revoked_at IS NULL
                    """,
                    (revoked_at, credential_record_id, user_id),
                )

            updated_row = connection.execute(
                """
                SELECT *
                FROM webauthn_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_record_id, user_id),
            ).fetchone()

        return self._credential_from_row(updated_row)

    def replace_recovery_codes(self, user_id, code_hashes):
        """Atomically rotate an owner's one-time recovery-code set.

        Only SHA-256 digests are persisted. Existing unused codes are
        invalidated in the same transaction as insertion of the new set.
        """
        self._validate_user_id(user_id)
        if not isinstance(code_hashes, (list, tuple)) or not code_hashes:
            raise ValueError("At least one recovery-code digest is required")
        if len(code_hashes) > 20 or len(set(code_hashes)) != len(code_hashes):
            raise ValueError("Recovery-code digests must be unique and bounded")
        for digest in code_hashes:
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                raise ValueError("Recovery-code digest must be lowercase SHA-256 hex")

        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            self._require_active_user(connection, user_id)
            connection.execute(
                """
                UPDATE webauthn_recovery_codes
                SET used_at = ?
                WHERE user_id = ? AND used_at IS NULL
                """,
                (now, user_id),
            )
            for digest in code_hashes:
                connection.execute(
                    """
                    INSERT INTO webauthn_recovery_codes
                        (id, user_id, code_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (str(uuid.uuid4()), user_id, digest, now),
                )
        return len(code_hashes)

    def count_active_recovery_codes(self, user_id):
        self._validate_user_id(user_id)
        row = self.database.connect().execute(
            """
            SELECT COUNT(*) AS total
            FROM webauthn_recovery_codes
            WHERE user_id = ? AND used_at IS NULL
            """,
            (user_id,),
        ).fetchone()
        return int(row["total"])

    _ALLOWED_CHALLENGE_PURPOSES = {
        "registration",
        "authentication",
        "tool_approval",
        "recovery",
    }

    @staticmethod
    def _challenge_from_row(row):
        if row is None:
            return None

        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "challenge_hash": row["challenge_hash"],
            "purpose": row["purpose"],
            "request_id": row["request_id"],
            "proposal_digest": row["proposal_digest"],
            "contract_fingerprint": row["contract_fingerprint"],
            "expires_at": row["expires_at"],
            "consumed_at": row["consumed_at"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _validate_challenge_expiry(expires_at):
        if not isinstance(expires_at, str) or not expires_at.strip():
            raise ValueError("expires_at must be a non-empty ISO 8601 string")

        try:
            parsed = datetime.fromisoformat(
                expires_at.strip().replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("expires_at must be a valid ISO 8601 timestamp") from exc

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")

        if parsed <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")

        return expires_at.strip()

    def create_challenge(
        self,
        *,
        user_id,
        challenge_hash,
        purpose,
        expires_at,
        request_id=None,
        proposal_digest=None,
        contract_fingerprint=None,
    ):
        self._validate_user_id(user_id)

        if (
            not isinstance(challenge_hash, str)
            or len(challenge_hash) != 64
            or any(c not in "0123456789abcdefABCDEF" for c in challenge_hash)
        ):
            raise ValueError("challenge_hash must be a 64-character SHA-256 hex digest")

        challenge_hash = challenge_hash.lower()

        if not isinstance(purpose, str) or purpose not in self._ALLOWED_CHALLENGE_PURPOSES:
            raise ValueError("Unsupported WebAuthn challenge purpose")

        expires_at = self._validate_challenge_expiry(expires_at)

        approval_metadata = (request_id, proposal_digest, contract_fingerprint)

        if purpose == "tool_approval":
            if any(
                not isinstance(value, str) or not value.strip()
                for value in approval_metadata
            ):
                raise ValueError(
                    "tool_approval challenges require request_id, proposal_digest, "
                    "and contract_fingerprint"
                )

            request_id = request_id.strip()
            proposal_digest = proposal_digest.strip()
            contract_fingerprint = contract_fingerprint.strip()
        elif any(value is not None for value in approval_metadata):
            raise ValueError(
                "Request and proposal metadata are only valid for tool_approval challenges"
            )

        challenge_record_id = str(uuid.uuid4())
        created_at = _utc_now()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            self._require_active_user(connection, user_id)

            connection.execute(
                """
                INSERT INTO webauthn_challenges (
                    id, user_id, challenge_hash, purpose,
                    request_id, proposal_digest, contract_fingerprint,
                    expires_at, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_record_id,
                    user_id,
                    challenge_hash,
                    purpose,
                    request_id,
                    proposal_digest,
                    contract_fingerprint,
                    expires_at,
                    created_at,
                ),
            )

            row = connection.execute(
                """
                SELECT *
                FROM webauthn_challenges
                WHERE id = ? AND user_id = ?
                """,
                (challenge_record_id, user_id),
            ).fetchone()

        return self._challenge_from_row(row)

    def get_challenge(self, user_id, challenge_record_id):
        self._validate_user_id(user_id)

        if (
            not isinstance(challenge_record_id, str)
            or not challenge_record_id.strip()
        ):
            raise ValueError("challenge_record_id must be a non-empty string")

        row = self.database.connect().execute(
            """
            SELECT *
            FROM webauthn_challenges
            WHERE id = ? AND user_id = ?
            """,
            (challenge_record_id, user_id),
        ).fetchone()

        return self._challenge_from_row(row)

    def consume_challenge(self, user_id, challenge_record_id):
        self._validate_user_id(user_id)

        if (
            not isinstance(challenge_record_id, str)
            or not challenge_record_id.strip()
        ):
            raise ValueError("challenge_record_id must be a non-empty string")

        consumed_at = _utc_now()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()

            row = connection.execute(
                """
                SELECT *
                FROM webauthn_challenges
                WHERE id = ? AND user_id = ?
                """,
                (challenge_record_id, user_id),
            ).fetchone()

            if row is None or row["consumed_at"] is not None:
                return None

            expiry = datetime.fromisoformat(
                row["expires_at"].replace("Z", "+00:00")
            )

            if expiry.tzinfo is None or expiry.utcoffset() is None:
                return None

            if expiry <= datetime.now(timezone.utc):
                return None

            updated = connection.execute(
                """
                UPDATE webauthn_challenges
                SET consumed_at = ?
                WHERE id = ? AND user_id = ? AND consumed_at IS NULL
                """,
                (consumed_at, challenge_record_id, user_id),
            )

            if updated.rowcount != 1:
                return None

            consumed_row = connection.execute(
                """
                SELECT *
                FROM webauthn_challenges
                WHERE id = ? AND user_id = ?
                """,
                (challenge_record_id, user_id),
            ).fetchone()

        return self._challenge_from_row(consumed_row)



    def commit_verified_authentication(
        self,
        *,
        user_id,
        challenge_record_id,
        credential_record_id,
        verified_sign_count,
    ):
        """Atomically consume a login challenge and update its passkey."""
        self._validate_user_id(user_id)

        for field_name, value in (
            ("challenge_record_id", challenge_record_id),
            ("credential_record_id", credential_record_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")

        self._validate_sign_count(verified_sign_count)

        now = datetime.now(timezone.utc)
        now_text = now.isoformat()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            self._require_active_user(connection, user_id)

            challenge = connection.execute(
                """
                SELECT *
                FROM webauthn_challenges
                WHERE id = ? AND user_id = ?
                """,
                (challenge_record_id, user_id),
            ).fetchone()

            if challenge is None:
                raise LookupError("WebAuthn challenge not found")

            if (
                challenge["purpose"] != "authentication"
                or challenge["consumed_at"] is not None
            ):
                raise PermissionError("Authentication challenge is unavailable")

            try:
                expiry = datetime.fromisoformat(
                    challenge["expires_at"].replace("Z", "+00:00")
                )
            except (TypeError, ValueError, AttributeError) as exc:
                raise PermissionError("Authentication challenge expiry is invalid") from exc

            if expiry.tzinfo is None or expiry.utcoffset() is None:
                raise PermissionError("Authentication challenge expiry has no timezone")

            if expiry <= now:
                raise PermissionError("Authentication challenge has expired")

            credential = connection.execute(
                """
                SELECT *
                FROM webauthn_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_record_id, user_id),
            ).fetchone()

            if credential is None:
                raise LookupError("WebAuthn credential not found")

            if credential["revoked_at"] is not None:
                raise PermissionError("WebAuthn credential is revoked")

            stored_count = credential["sign_count"]
            if stored_count != 0 and verified_sign_count != 0:
                if verified_sign_count <= stored_count:
                    raise PermissionError("WebAuthn signature counter did not advance")

            # Synced passkeys may legitimately report a zero counter.
            updated_count = max(stored_count, verified_sign_count)

            consumed = connection.execute(
                """
                UPDATE webauthn_challenges
                SET consumed_at = ?
                WHERE id = ? AND user_id = ?
                  AND purpose = 'authentication'
                  AND consumed_at IS NULL
                """,
                (now_text, challenge_record_id, user_id),
            )
            if consumed.rowcount != 1:
                raise PermissionError("Authentication challenge was already consumed")

            updated = connection.execute(
                """
                UPDATE webauthn_credentials
                SET sign_count = ?, last_used_at = ?
                WHERE id = ? AND user_id = ? AND revoked_at IS NULL
                """,
                (updated_count, now_text, credential_record_id, user_id),
            )
            if updated.rowcount != 1:
                raise PermissionError("WebAuthn credential is no longer active")

            row = connection.execute(
                """
                SELECT *
                FROM webauthn_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_record_id, user_id),
            ).fetchone()

        return self._credential_from_row(row)

    def commit_verified_tool_authorization(
        self,
        *,
        user_id,
        request_id,
        challenge_record_id,
        credential_record_id,
        verified_sign_count,
    ):
        """Commit authorization after a separate service verifies the assertion."""
        self._validate_user_id(user_id)

        for field_name, value in (
            ("request_id", request_id),
            ("challenge_record_id", challenge_record_id),
            ("credential_record_id", credential_record_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")

        self._validate_sign_count(verified_sign_count)

        from backend.app.persistence.tool_requests import _request_digest

        now = datetime.now(timezone.utc)
        now_text = now.isoformat()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            self._require_active_user(connection, user_id)

            request = connection.execute(
                """
                SELECT * FROM tool_requests
                WHERE id = ? AND user_id = ?
                """,
                (request_id, user_id),
            ).fetchone()

            if request is None:
                raise LookupError("Tool request not found")

            if request["status"] != "pending" or request["consumed_at"] is not None:
                raise PermissionError("Tool request is not awaiting passkey authorization")

            if request["authorization_policy"] != "passkey":
                raise PermissionError(
                    "Tool request is not authorized for passkey approval"
                )

            request_expires_at = request["expires_at"]

            if not isinstance(request_expires_at, str) or not request_expires_at.strip():
                raise PermissionError("Tool request expiry is required")

            try:
                request_expiry = datetime.fromisoformat(
                    request_expires_at.replace("Z", "+00:00")
                )
            except (TypeError, ValueError) as exc:
                raise PermissionError("Tool request expiry is invalid") from exc

            if request_expiry.tzinfo is None or request_expiry.utcoffset() is None:
                raise PermissionError("Tool request expiry must include a timezone")

            if request_expiry <= now:
                raise PermissionError("Tool request has expired")

            fingerprint = request["contract_fingerprint"]
            if (
                not isinstance(fingerprint, str)
                or len(fingerprint) != 64
                or any(char not in "0123456789abcdef" for char in fingerprint)
            ):
                raise PermissionError("Tool request has no valid contract fingerprint")

            try:
                arguments = json.loads(request["arguments_json"])
                audit = json.loads(request["audit_json"] or "{}")
                current_digest = _request_digest(
                    request["tool_id"],
                    arguments,
                    fingerprint,
                )
            except (TypeError, ValueError) as exc:
                raise PermissionError("Tool request proposal data is invalid") from exc

            proposal = audit.get("proposal") if isinstance(audit, dict) else None
            if (
                not isinstance(proposal, dict)
                or proposal.get("arguments_sha256") != current_digest
                or proposal.get("contract_fingerprint") != fingerprint
            ):
                raise PermissionError("Tool request proposal has changed")

            challenge = connection.execute(
                """
                SELECT * FROM webauthn_challenges
                WHERE id = ? AND user_id = ?
                """,
                (challenge_record_id, user_id),
            ).fetchone()

            if challenge is None:
                raise LookupError("WebAuthn challenge not found")

            if (
                challenge["purpose"] != "tool_approval"
                or challenge["request_id"] != request_id
                or challenge["proposal_digest"] != current_digest
                or challenge["contract_fingerprint"] != fingerprint
                or challenge["consumed_at"] is not None
            ):
                raise PermissionError("WebAuthn challenge does not match this request")

            try:
                challenge_expiry = datetime.fromisoformat(
                    challenge["expires_at"].replace("Z", "+00:00")
                )
            except (TypeError, ValueError) as exc:
                raise PermissionError("WebAuthn challenge expiry is invalid") from exc

            if challenge_expiry.tzinfo is None or challenge_expiry.utcoffset() is None:
                raise PermissionError("WebAuthn challenge expiry must include a timezone")

            if challenge_expiry <= now:
                raise PermissionError("WebAuthn challenge has expired")

            credential = connection.execute(
                """
                SELECT * FROM webauthn_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_record_id, user_id),
            ).fetchone()

            if credential is None:
                raise LookupError("WebAuthn credential not found")

            if credential["revoked_at"] is not None:
                raise PermissionError("WebAuthn credential has been revoked")

            stored_count = credential["sign_count"]
            if stored_count != 0 and verified_sign_count != 0:
                if verified_sign_count <= stored_count:
                    raise PermissionError("WebAuthn signature counter did not advance")

            # Synced passkeys may legitimately report zero counters.
            updated_count = max(stored_count, verified_sign_count)
            authorization_id = str(uuid.uuid4())

            challenge_update = connection.execute(
                """
                UPDATE webauthn_challenges
                SET consumed_at = ?
                WHERE id = ? AND user_id = ? AND consumed_at IS NULL
                """,
                (now_text, challenge_record_id, user_id),
            )
            if challenge_update.rowcount != 1:
                raise PermissionError("WebAuthn challenge has already been consumed")

            credential_update = connection.execute(
                """
                UPDATE webauthn_credentials
                SET sign_count = ?, last_used_at = ?
                WHERE id = ? AND user_id = ? AND revoked_at IS NULL
                """,
                (updated_count, now_text, credential_record_id, user_id),
            )
            if credential_update.rowcount != 1:
                raise PermissionError("WebAuthn credential is no longer active")

            connection.execute(
                """
                INSERT INTO tool_authorizations (
                    id, user_id, request_id, challenge_id, credential_id,
                    proposal_digest, contract_fingerprint, authorized_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authorization_id,
                    user_id,
                    request_id,
                    challenge_record_id,
                    credential_record_id,
                    current_digest,
                    fingerprint,
                    now_text,
                ),
            )

            request_update = connection.execute(
                """
                UPDATE tool_requests
                SET status = 'approved', updated_at = ?
                WHERE id = ? AND user_id = ?
                  AND status = 'pending' AND consumed_at IS NULL
                """,
                (now_text, request_id, user_id),
            )
            if request_update.rowcount != 1:
                raise PermissionError("Tool request is no longer awaiting authorization")

        return {
            "id": authorization_id,
            "user_id": user_id,
            "request_id": request_id,
            "challenge_id": challenge_record_id,
            "credential_id": credential_record_id,
            "proposal_digest": current_digest,
            "contract_fingerprint": fingerprint,
            "authorized_at": now_text,
        }

    def commit_verified_registration(
        self,
        *,
        user_id,
        challenge_record_id,
        credential_id,
        public_key,
        sign_count=0,
        transports=(),
        device_type=None,
        backed_up=False,
        name=None,
    ):
        """Atomically save a verified passkey and consume its registration challenge."""
        self._validate_user_id(user_id)

        if (
            not isinstance(challenge_record_id, str)
            or not challenge_record_id.strip()
        ):
            raise ValueError(
                "challenge_record_id must be a non-empty string"
            )

        self._validate_credential_id(credential_id)
        public_key = self._validate_public_key(public_key)
        self._validate_sign_count(sign_count)

        if isinstance(transports, (str, bytes)):
            raise ValueError("transports must be a collection of strings")

        try:
            transports = list(transports)
        except TypeError as exc:
            raise ValueError(
                "transports must be a collection of strings"
            ) from exc

        if any(
            not isinstance(item, str)
            or item not in self._ALLOWED_TRANSPORTS
            for item in transports
        ):
            raise ValueError("transports contains an unsupported value")

        transports = list(dict.fromkeys(transports))

        if (
            device_type is not None
            and device_type not in self._ALLOWED_DEVICE_TYPES
        ):
            raise ValueError("Unsupported WebAuthn device_type")

        if not isinstance(backed_up, bool):
            raise ValueError("backed_up must be a boolean")

        if name is not None:
            if not isinstance(name, str) or not name.strip():
                raise ValueError("name must be a non-empty string or None")
            if len(name) > 128:
                raise ValueError("name must not exceed 128 characters")
            name = name.strip()

        now = datetime.now(timezone.utc)
        now_text = now.isoformat()
        credential_record_id = str(uuid.uuid4())

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            self._require_active_user(connection, user_id)

            challenge = connection.execute(
                """
                SELECT *
                FROM webauthn_challenges
                WHERE id = ? AND user_id = ?
                """,
                (challenge_record_id, user_id),
            ).fetchone()

            if challenge is None:
                raise LookupError("WebAuthn challenge not found")

            if challenge["purpose"] != "registration":
                raise PermissionError(
                    "WebAuthn challenge is not for registration"
                )

            if challenge["consumed_at"] is not None:
                raise PermissionError(
                    "WebAuthn registration challenge has already been consumed"
                )

            try:
                expiry = datetime.fromisoformat(
                    challenge["expires_at"].replace("Z", "+00:00")
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise PermissionError(
                    "WebAuthn registration challenge expiry is invalid"
                ) from exc

            if expiry.tzinfo is None or expiry.utcoffset() is None:
                raise PermissionError(
                    "WebAuthn registration challenge expiry must include a timezone"
                )

            if expiry <= now:
                raise PermissionError(
                    "WebAuthn registration challenge has expired"
                )

            connection.execute(
                """
                INSERT INTO webauthn_credentials (
                    id,
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    transports_json,
                    device_type,
                    backed_up,
                    name,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    credential_record_id,
                    user_id,
                    credential_id,
                    sqlite3.Binary(public_key),
                    sign_count,
                    json.dumps(transports),
                    device_type,
                    int(backed_up),
                    name,
                    now_text,
                ),
            )

            consumed = connection.execute(
                """
                UPDATE webauthn_challenges
                SET consumed_at = ?
                WHERE id = ?
                  AND user_id = ?
                  AND purpose = 'registration'
                  AND consumed_at IS NULL
                """,
                (now_text, challenge_record_id, user_id),
            )

            if consumed.rowcount != 1:
                raise PermissionError(
                    "WebAuthn registration challenge has already been consumed"
                )

            row = connection.execute(
                """
                SELECT *
                FROM webauthn_credentials
                WHERE id = ? AND user_id = ?
                """,
                (credential_record_id, user_id),
            ).fetchone()

        return self._credential_from_row(row)

