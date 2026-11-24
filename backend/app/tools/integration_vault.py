"""AES-256-GCM integration credential vault.

The encryption key is supplied by the deployment environment/key manager and is
never generated, persisted, logged, or returned by this module.
"""
import base64
import binascii
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.persistence.database import Database


class IntegrationVaultUnavailable(RuntimeError):
    pass


class IntegrationSecretVault:
    def __init__(self, database: Database, key_b64: str | None) -> None:
        self.database = database
        self._key: bytes | None = None
        if key_b64 is not None:
            try:
                key = base64.b64decode(key_b64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("Integration vault key is invalid") from exc
            if len(key) != 32:
                raise ValueError("Integration vault key must decode to exactly 32 bytes")
            self._key = key

    @property
    def available(self) -> bool:
        return self._key is not None

    def _cipher(self) -> AESGCM:
        if self._key is None:
            raise IntegrationVaultUnavailable("Integration credential vault is not configured")
        return AESGCM(self._key)

    @staticmethod
    def _aad(user_id: str, connection_id: str, integration_id: str, secret_ref: str) -> bytes:
        return ("aibrain-integration-v1|" + "|".join(
            (user_id, connection_id, integration_id, secret_ref)
        )).encode("utf-8")

    def store(
        self,
        user_id: str,
        connection_id: str,
        integration_id: str,
        credentials: dict[str, Any],
    ) -> str:
        if not isinstance(credentials, dict) or not credentials:
            raise ValueError("Credential payload must be a non-empty object")
        try:
            plaintext = json.dumps(
                credentials, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("Credential payload is invalid") from exc
        if len(plaintext) > 65_536:
            raise ValueError("Credential payload exceeds the vault limit")

        secret_ref = "vault:" + str(uuid.uuid4())
        nonce = secrets.token_bytes(12)
        ciphertext = self._cipher().encrypt(
            nonce, plaintext,
            self._aad(user_id, connection_id, integration_id, secret_ref),
        )
        with self.database.transaction(immediate=True):
            self.database.connect().execute(
                """INSERT INTO integration_secrets
                   (secret_ref,user_id,connection_id,integration_id,nonce,
                    ciphertext,key_version,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,1,datetime('now'),datetime('now'))""",
                (secret_ref, user_id, connection_id, integration_id, nonce, ciphertext),
            )
        return secret_ref

    def load(
        self, user_id: str, connection_id: str, integration_id: str
    ) -> dict[str, Any]:
        row = self.database.connect().execute(
            """SELECT s.secret_ref,s.nonce,s.ciphertext
               FROM integration_secrets s
               JOIN integration_connections c
                 ON c.id=s.connection_id AND c.user_id=s.user_id
               WHERE s.user_id=? AND s.connection_id=? AND s.integration_id=?
                 AND c.integration_id=? AND c.status='active'
                 AND c.secret_ref=s.secret_ref
                 AND (c.expires_at IS NULL OR c.expires_at>?)""",
            (user_id, connection_id, integration_id,
             integration_id, datetime.now(timezone.utc).isoformat()),
        ).fetchone()
        if row is None:
            raise LookupError("Active integration credentials are unavailable")
        try:
            plaintext = self._cipher().decrypt(
                row["nonce"], row["ciphertext"],
                self._aad(user_id, connection_id, integration_id, row["secret_ref"]),
            )
            value = json.loads(plaintext)
        except Exception:
            # Do not expose crypto or parser details that may contain sensitive data.
            raise IntegrationVaultUnavailable("Integration credentials could not be opened") from None
        if not isinstance(value, dict):
            raise IntegrationVaultUnavailable("Integration credential payload is invalid")
        return value

    def rotate(
        self,
        user_id: str,
        connection_id: str,
        integration_id: str,
        credentials: dict[str, Any],
    ) -> str:
        row = self.database.connect().execute(
            """SELECT secret_ref FROM integration_secrets
               WHERE user_id=? AND connection_id=? AND integration_id=?""",
            (user_id, connection_id, integration_id),
        ).fetchone()
        if row is None:
            raise LookupError("Integration credentials are unavailable")
        if not isinstance(credentials, dict) or not credentials:
            raise ValueError("Credential payload must be a non-empty object")
        try:
            plaintext = json.dumps(
                credentials, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("Credential payload is invalid") from exc
        if len(plaintext) > 65_536:
            raise ValueError("Credential payload exceeds the vault limit")
        secret_ref = row["secret_ref"]
        nonce = secrets.token_bytes(12)
        ciphertext = self._cipher().encrypt(
            nonce, plaintext,
            self._aad(user_id, connection_id, integration_id, secret_ref),
        )
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """UPDATE integration_secrets
                   SET nonce=?,ciphertext=?,key_version=key_version+1,
                       updated_at=datetime('now')
                   WHERE secret_ref=? AND user_id=? AND connection_id=?""",
                (nonce, ciphertext, secret_ref, user_id, connection_id),
            )
            if cursor.rowcount != 1:
                raise LookupError("Integration credentials are unavailable")
        return secret_ref
