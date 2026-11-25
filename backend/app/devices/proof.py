"""Ed25519 proof-of-possession for pending device enrollment."""
import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from backend.app.persistence.database import Database


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64decode(value: str, *, expected_length: int | None = None) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError("Invalid base64 encoding") from None
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("Invalid encoded length")
    return decoded


def _signed_message(
    challenge_id: str,
    device_id: str,
    owner_id: str,
    expires_at: str,
    nonce: str,
) -> bytes:
    return (
        "AIBRAIN_DEVICE_AUTH_V1\\n"
        f"{challenge_id}\\n{device_id}\\n{owner_id}\\n{expires_at}\\n{nonce}"
    ).encode("utf-8")


class DeviceProofRepository:
    """Stores public keys and consumes one-time Ed25519 challenges atomically."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def register_public_key(
        self, owner_id: str, device_id: str, public_key_b64: str
    ) -> None:
        public_key = _b64decode(public_key_b64, expected_length=32)
        fingerprint = hashlib.sha256(public_key).hexdigest()
        with self.database.transaction(immediate=True):
            cursor = self.database.connect().execute(
                """
                UPDATE devices
                SET public_key_b64 = ?
                WHERE id = ? AND user_id = ? AND status = 'pending'
                  AND public_key_fingerprint = ?
                  AND (public_key_b64 IS NULL OR public_key_b64 = ?)
                """,
                (base64.b64encode(public_key).decode("ascii"), device_id,
                 owner_id, fingerprint,
                 base64.b64encode(public_key).decode("ascii")),
            )
            if cursor.rowcount != 1:
                row = self.database.connect().execute(
                    "SELECT id FROM devices WHERE id=? AND user_id=? AND status='pending'",
                    (device_id, owner_id),
                ).fetchone()
                if row is None:
                    raise LookupError("Pending device not found")
                raise ValueError("Public key does not match enrolled fingerprint")

    def create_challenge(self, owner_id: str, device_id: str) -> dict:
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(32)
        now = _now()
        expires = now + timedelta(minutes=5)
        expires_text = expires.isoformat()
        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                """
                SELECT id FROM devices
                WHERE id=? AND user_id=? AND status='pending'
                  AND public_key_b64 IS NOT NULL
                """,
                (device_id, owner_id),
            ).fetchone()
            if row is None:
                raise LookupError("Pending keyed device not found")
            self.database.connect().execute(
                """
                INSERT INTO device_auth_challenges
                    (id, device_id, user_id, nonce_hash, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (challenge_id, device_id, owner_id,
                 hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                 expires_text, now.isoformat()),
            )
        message = _signed_message(
            challenge_id, device_id, owner_id, expires_text, nonce
        )
        return {
            "challenge_id": challenge_id,
            "device_id": device_id,
            "nonce": nonce,
            "expires_at": expires_text,
            "message_b64": base64.b64encode(message).decode("ascii"),
        }

    def verify_and_activate(
        self,
        owner_id: str,
        device_id: str,
        challenge_id: str,
        nonce: str,
        signature_b64: str,
    ) -> None:
        signature = _b64decode(signature_b64, expected_length=64)
        if not isinstance(nonce, str) or not nonce.isascii() or not 20 <= len(nonce) <= 128:
            raise ValueError("Invalid challenge nonce")
        now = _now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT c.nonce_hash, c.expires_at, c.used_at, d.public_key_b64
                FROM device_auth_challenges c
                JOIN devices d ON d.id=c.device_id AND d.user_id=c.user_id
                JOIN users u ON u.id=c.user_id
                WHERE c.id=? AND c.device_id=? AND c.user_id=?
                  AND d.status='pending' AND u.deleted_at IS NULL
                """,
                (challenge_id, device_id, owner_id),
            ).fetchone()
            if row is None:
                raise LookupError("Device challenge not found")
            if row["used_at"] is not None:
                raise ValueError("Device challenge already used")
            if datetime.fromisoformat(row["expires_at"]) <= now:
                raise ValueError("Device challenge expired")
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            if not secrets.compare_digest(nonce_hash, row["nonce_hash"]):
                raise ValueError("Device challenge nonce mismatch")
            public_key = _b64decode(row["public_key_b64"], expected_length=32)
            message = _signed_message(
                challenge_id, device_id, owner_id, row["expires_at"], nonce
            )
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            except (InvalidSignature, ValueError):
                raise PermissionError("Device proof rejected") from None

            connection.execute(
                """
                UPDATE device_auth_challenges SET used_at=?
                WHERE id=? AND used_at IS NULL
                """,
                (now.isoformat(), challenge_id),
            )
            connection.execute(
                """
                UPDATE devices SET status='active', last_seen_at=?
                WHERE id=? AND user_id=? AND status='pending'
                """,
                (now.isoformat(), device_id, owner_id),
            )
