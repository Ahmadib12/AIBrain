"""Ed25519 proof-of-possession for pending device enrollment."""
import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from backend.app.persistence.contracts import DatabaseProtocol


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
    purpose: str,
) -> bytes:
    return (
        f"AIBRAIN_DEVICE_{purpose.upper()}_V1\n"
        f"{challenge_id}\n{device_id}\n{owner_id}\n{expires_at}\n{nonce}"
    ).encode("utf-8")


class DeviceProofRepository:
    """Stores public keys and consumes one-time Ed25519 challenges atomically."""

    def __init__(self, database: DatabaseProtocol) -> None:
        self.database = database

    def _transaction(self):
        """Keep SQLite writer serialization; use explicit PostgreSQL row locks."""
        dialect = getattr(self.database, "dialect", None)
        if dialect not in {"sqlite", "postgresql"}:
            raise RuntimeError("Unsupported database dialect for device proof")
        return self.database.transaction(immediate=(dialect == "sqlite"))

    def _lock_owner_device(self, connection, owner_id: str, device_id: str) -> None:
        """Lock account then device, matching IdentityRepository lock order."""
        if getattr(self.database, "dialect", None) != "postgresql":
            return
        owner = connection.execute(
            "SELECT id FROM users WHERE id=? AND deleted_at IS NULL FOR UPDATE",
            (owner_id,),
        ).fetchone()
        if owner is None:
            raise LookupError("Active device owner not found")
        device = connection.execute(
            "SELECT id FROM devices WHERE id=? AND user_id=? FOR UPDATE",
            (device_id, owner_id),
        ).fetchone()
        if device is None:
            raise LookupError("Device not found")

    def _lock_device_owner(self, connection, device_id: str) -> str:
        """Resolve an unauthenticated device owner, then lock owner before device."""
        row = connection.execute(
            "SELECT user_id FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Active keyed device not found")
        owner_id = row["user_id"]
        self._lock_owner_device(connection, owner_id, device_id)
        return owner_id

    def register_public_key(
        self, owner_id: str, device_id: str, public_key_b64: str
    ) -> None:
        public_key = _b64decode(public_key_b64, expected_length=32)
        fingerprint = hashlib.sha256(public_key).hexdigest()
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            cursor = connection.execute(
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

    def create_challenge(
        self, owner_id: str, device_id: str, *, purpose: str = "enrollment"
    ) -> dict:
        if purpose not in {"enrollment", "session"}:
            raise ValueError("Unsupported device challenge purpose")
        required_status = "pending" if purpose == "enrollment" else "active"
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(32)
        now = _now()
        expires = now + timedelta(minutes=5)
        expires_text = expires.isoformat()
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            row = connection.execute(
                """
                SELECT id FROM devices
                WHERE id=? AND user_id=? AND status=?
                  AND public_key_b64 IS NOT NULL
                """,
                (device_id, owner_id, required_status),
            ).fetchone()
            if row is None:
                raise LookupError("Pending keyed device not found")

            # Bound challenge issuance to reduce database and signing abuse.
            cutoff = (now - timedelta(minutes=5)).isoformat()
            recent = connection.execute(
                """
                SELECT COUNT(*) AS total FROM device_auth_challenges
                WHERE device_id=? AND user_id=? AND purpose=? AND created_at > ?
                """,
                (device_id, owner_id, purpose, cutoff),
            ).fetchone()["total"]
            if recent >= 10:
                raise PermissionError("Device challenge rate limit exceeded")

            # Opportunistic bounded cleanup; expired challenges are never valid.
            connection.execute(
                """
                DELETE FROM device_auth_challenges
                WHERE expires_at <= ?
                   OR (used_at IS NOT NULL AND used_at <= ?)
                """,
                (now.isoformat(), (now - timedelta(days=1)).isoformat()),
            )
            connection.execute(
                """
                INSERT INTO device_auth_challenges
                    (id, device_id, user_id, nonce_hash, expires_at, created_at, purpose)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (challenge_id, device_id, owner_id,
                 hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                 expires_text, now.isoformat(), purpose),
            )
        message = _signed_message(
            challenge_id, device_id, owner_id, expires_text, nonce, purpose
        )
        return {
            "challenge_id": challenge_id,
            "device_id": device_id,
            "nonce": nonce,
            "expires_at": expires_text,
            "message_b64": base64.b64encode(message).decode("ascii"),
        }


    def create_login_challenge(self, device_id: str) -> dict:
        """Issue a session-purpose challenge without requiring an account session.

        The account owner is resolved only from the active device record.
        """
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(32)
        now = _now()
        expires_text = (now + timedelta(minutes=5)).isoformat()
        with self._transaction():
            connection = self.database.connect()
            owner_id = self._lock_device_owner(connection, device_id)
            device = connection.execute(
                """
                SELECT d.user_id
                FROM devices d
                JOIN users u ON u.id=d.user_id
                WHERE d.id=? AND d.status='active'
                  AND d.public_key_b64 IS NOT NULL
                  AND u.deleted_at IS NULL
                """,
                (device_id,),
            ).fetchone()
            if device is None:
                raise LookupError("Active keyed device not found")
            owner_id = device["user_id"]
            cutoff = (now - timedelta(minutes=5)).isoformat()
            recent = connection.execute(
                """
                SELECT COUNT(*) AS total FROM device_auth_challenges
                WHERE device_id=? AND user_id=? AND purpose='session'
                  AND created_at > ?
                """,
                (device_id, owner_id, cutoff),
            ).fetchone()["total"]
            if recent >= 10:
                raise PermissionError("Device challenge rate limit exceeded")
            connection.execute(
                """
                DELETE FROM device_auth_challenges
                WHERE expires_at <= ?
                   OR (used_at IS NOT NULL AND used_at <= ?)
                """,
                (now.isoformat(), (now - timedelta(days=1)).isoformat()),
            )
            connection.execute(
                """
                INSERT INTO device_auth_challenges
                    (id, device_id, user_id, nonce_hash, expires_at, created_at, purpose)
                VALUES (?, ?, ?, ?, ?, ?, 'session')
                """,
                (
                    challenge_id, device_id, owner_id,
                    hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                    expires_text, now.isoformat(),
                ),
            )
        message = _signed_message(
            challenge_id, device_id, owner_id, expires_text, nonce, "session"
        )
        return {
            "challenge_id": challenge_id,
            "device_id": device_id,
            "nonce": nonce,
            "expires_at": expires_text,
            "message_b64": base64.b64encode(message).decode("ascii"),
        }

    def verify_login_proof(
        self,
        device_id: str,
        challenge_id: str,
        nonce: str,
        signature_b64: str,
    ) -> str:
        """Verify and consume an unauthenticated device login proof.

        Returns the owner ID from the trusted device/challenge rows. The
        caller must still create the session through IdentityRepository,
        which atomically rechecks that the account and device remain active.
        """
        signature = _b64decode(signature_b64, expected_length=64)
        if not isinstance(nonce, str) or not nonce.isascii() or not 20 <= len(nonce) <= 128:
            raise ValueError("Invalid challenge nonce")
        now = _now()
        with self._transaction():
            connection = self.database.connect()
            owner_row = connection.execute(
                "SELECT user_id FROM device_auth_challenges WHERE id=? AND device_id=? AND purpose='session'",
                (challenge_id, device_id),
            ).fetchone()
            if owner_row is None:
                raise LookupError("Device login challenge not found")
            owner_id = owner_row["user_id"]
            self._lock_owner_device(connection, owner_id, device_id)
            row = connection.execute(
                """
                SELECT c.user_id, c.nonce_hash, c.expires_at, c.used_at,
                       d.public_key_b64
                FROM device_auth_challenges c
                JOIN devices d ON d.id=c.device_id AND d.user_id=c.user_id
                JOIN users u ON u.id=c.user_id
                WHERE c.id=? AND c.device_id=? AND c.purpose='session'
                  AND d.status='active' AND d.public_key_b64 IS NOT NULL
                  AND u.deleted_at IS NULL
                """,
                (challenge_id, device_id),
            ).fetchone()
            if row is None:
                raise LookupError("Device login challenge not found")
            if row["used_at"] is not None:
                raise ValueError("Device challenge already used")
            if datetime.fromisoformat(row["expires_at"]) <= now:
                raise ValueError("Device challenge expired")
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            if not secrets.compare_digest(nonce_hash, row["nonce_hash"]):
                raise ValueError("Device challenge nonce mismatch")
            owner_id = row["user_id"]
            public_key = _b64decode(row["public_key_b64"], expected_length=32)
            message = _signed_message(
                challenge_id, device_id, owner_id, row["expires_at"], nonce, "session"
            )
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            except (InvalidSignature, ValueError):
                raise PermissionError("Device login proof rejected") from None
            consumed = connection.execute(
                """
                UPDATE device_auth_challenges SET used_at=?
                WHERE id=? AND device_id=? AND purpose='session' AND used_at IS NULL
                """,
                (now.isoformat(), challenge_id, device_id),
            )
            if consumed.rowcount != 1:
                raise ValueError("Device challenge already used")
            touched = connection.execute(
                """
                UPDATE devices SET last_seen_at=?
                WHERE id=? AND user_id=? AND status='active'
                """,
                (now.isoformat(), device_id, owner_id),
            )
            if touched.rowcount != 1:
                raise ValueError("Device is no longer active")
        return owner_id


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
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            row = connection.execute(
                """
                SELECT c.nonce_hash, c.expires_at, c.used_at, d.public_key_b64
                FROM device_auth_challenges c
                JOIN devices d ON d.id=c.device_id AND d.user_id=c.user_id
                JOIN users u ON u.id=c.user_id
                WHERE c.id=? AND c.device_id=? AND c.user_id=?
                  AND d.status='pending' AND c.purpose='enrollment'
                  AND u.deleted_at IS NULL
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
                challenge_id, device_id, owner_id, row["expires_at"], nonce,
                "enrollment"
            )
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            except (InvalidSignature, ValueError):
                raise PermissionError("Device proof rejected") from None

            consumed = connection.execute(
                """
                UPDATE device_auth_challenges SET used_at=?
                WHERE id=? AND purpose='enrollment' AND used_at IS NULL
                """,
                (now.isoformat(), challenge_id),
            )
            if consumed.rowcount != 1:
                raise ValueError("Device challenge already used")
            activated = connection.execute(
                """
                UPDATE devices SET status='active', last_seen_at=?
                WHERE id=? AND user_id=? AND status='pending'
                """,
                (now.isoformat(), device_id, owner_id),
            )
            if activated.rowcount != 1:
                raise ValueError("Device activation state changed")


    def verify_session_proof(
        self,
        owner_id: str,
        device_id: str,
        challenge_id: str,
        nonce: str,
        signature_b64: str,
    ) -> None:
        """Consume a one-time proof from an already-active device."""
        signature = _b64decode(signature_b64, expected_length=64)
        if not isinstance(nonce, str) or not nonce.isascii() or not 20 <= len(nonce) <= 128:
            raise ValueError("Invalid challenge nonce")
        now = _now()
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            row = connection.execute(
                """
                SELECT c.nonce_hash, c.expires_at, c.used_at, d.public_key_b64
                FROM device_auth_challenges c
                JOIN devices d ON d.id=c.device_id AND d.user_id=c.user_id
                JOIN users u ON u.id=c.user_id
                WHERE c.id=? AND c.device_id=? AND c.user_id=?
                  AND c.purpose='session' AND d.status='active'
                  AND u.deleted_at IS NULL
                """,
                (challenge_id, device_id, owner_id),
            ).fetchone()
            if row is None:
                raise LookupError("Device session challenge not found")
            if row["used_at"] is not None:
                raise ValueError("Device challenge already used")
            if datetime.fromisoformat(row["expires_at"]) <= now:
                raise ValueError("Device challenge expired")
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            if not secrets.compare_digest(nonce_hash, row["nonce_hash"]):
                raise ValueError("Device challenge nonce mismatch")
            public_key = _b64decode(row["public_key_b64"], expected_length=32)
            message = _signed_message(
                challenge_id, device_id, owner_id, row["expires_at"], nonce,
                "session"
            )
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            except (InvalidSignature, ValueError):
                raise PermissionError("Device session proof rejected") from None

            consumed = connection.execute(
                """
                UPDATE device_auth_challenges SET used_at=?
                WHERE id=? AND purpose='session' AND used_at IS NULL
                """,
                (now.isoformat(), challenge_id),
            )
            if consumed.rowcount != 1:
                raise ValueError("Device challenge already used")
            touched = connection.execute(
                """
                UPDATE devices SET last_seen_at=?
                WHERE id=? AND user_id=? AND status='active'
                """,
                (now.isoformat(), device_id, owner_id),
            )
            if touched.rowcount != 1:
                raise ValueError("Device is no longer active")

    def create_key_rotation_challenge(
        self, owner_id: str, device_id: str, new_public_key_b64: str
    ) -> dict:
        """Create a short-lived challenge requiring both old and replacement keys."""
        new_public_key = _b64decode(new_public_key_b64, expected_length=32)
        canonical_key = base64.b64encode(new_public_key).decode("ascii")
        new_fingerprint = hashlib.sha256(new_public_key).hexdigest()
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(32)
        now = _now()
        expires_text = (now + timedelta(minutes=5)).isoformat()
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            device = connection.execute(
                """
                SELECT public_key_b64, public_key_fingerprint FROM devices
                WHERE id=? AND user_id=? AND status='active'
                  AND public_key_b64 IS NOT NULL
                """,
                (device_id, owner_id),
            ).fetchone()
            if device is None:
                raise LookupError("Active keyed device not found")
            if secrets.compare_digest(device["public_key_fingerprint"], new_fingerprint):
                raise ValueError("Replacement key must differ from the current key")
            cutoff = (now - timedelta(minutes=5)).isoformat()
            recent = connection.execute(
                """
                SELECT COUNT(*) AS total FROM device_key_rotation_challenges
                WHERE device_id=? AND user_id=? AND created_at>?
                """,
                (device_id, owner_id, cutoff),
            ).fetchone()["total"]
            if recent >= 5:
                raise PermissionError("Device key rotation rate limit exceeded")
            connection.execute(
                """
                DELETE FROM device_key_rotation_challenges
                WHERE expires_at<=? OR (used_at IS NOT NULL AND used_at<=?)
                """,
                (now.isoformat(), (now - timedelta(days=1)).isoformat()),
            )
            connection.execute(
                """
                INSERT INTO device_key_rotation_challenges
                    (id,device_id,user_id,nonce_hash,previous_fingerprint,proposed_public_key_b64,
                     proposed_fingerprint,expires_at,created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (challenge_id, device_id, owner_id,
                 hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                 device["public_key_fingerprint"], canonical_key, new_fingerprint,
                 expires_text, now.isoformat()),
            )
        message = (
            f"AIBRAIN_DEVICE_KEY_ROTATION_V1\n{challenge_id}\n{device_id}\n"
            f"{owner_id}\n{expires_text}\n{nonce}\n{new_fingerprint}"
        ).encode("utf-8")
        return {
            "challenge_id": challenge_id, "device_id": device_id, "nonce": nonce,
            "expires_at": expires_text,
            "new_public_key_fingerprint": new_fingerprint,
            "message_b64": base64.b64encode(message).decode("ascii"),
        }

    def verify_and_rotate_key(
        self, owner_id: str, device_id: str, challenge_id: str, nonce: str,
        old_signature_b64: str, new_signature_b64: str,
    ) -> str:
        """Verify both keys and atomically rotate, revoke sessions and append audit."""
        old_signature = _b64decode(old_signature_b64, expected_length=64)
        new_signature = _b64decode(new_signature_b64, expected_length=64)
        if not isinstance(nonce, str) or not nonce.isascii() or not 20 <= len(nonce) <= 128:
            raise ValueError("Invalid challenge nonce")
        now = _now()
        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            row = connection.execute(
                """
                SELECT c.nonce_hash,c.expires_at,c.used_at,c.applied_at,
                       c.previous_fingerprint,c.proposed_public_key_b64,c.proposed_fingerprint,
                       d.public_key_b64,d.public_key_fingerprint
                FROM device_key_rotation_challenges c
                JOIN devices d ON d.id=c.device_id AND d.user_id=c.user_id
                JOIN users u ON u.id=c.user_id
                WHERE c.id=? AND c.device_id=? AND c.user_id=?
                  AND d.status='active' AND u.deleted_at IS NULL
                """,
                (challenge_id, device_id, owner_id),
            ).fetchone()
            if row is None:
                raise LookupError("Device key rotation challenge not found")
            if row["used_at"] is not None or row["applied_at"] is not None:
                raise ValueError("Device key rotation challenge already used")
            if not secrets.compare_digest(
                row["previous_fingerprint"], row["public_key_fingerprint"]
            ):
                raise ValueError("Device key changed after this challenge was issued")
            if datetime.fromisoformat(row["expires_at"]) <= now:
                raise ValueError("Device key rotation challenge expired")
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            if not secrets.compare_digest(nonce_hash, row["nonce_hash"]):
                raise ValueError("Device key rotation nonce mismatch")
            message = (
                f"AIBRAIN_DEVICE_KEY_ROTATION_V1\n{challenge_id}\n{device_id}\n"
                f"{owner_id}\n{row['expires_at']}\n{nonce}\n{row['proposed_fingerprint']}"
            ).encode("utf-8")
            try:
                old_public_key = _b64decode(row["public_key_b64"], expected_length=32)
                new_public_key = _b64decode(row["proposed_public_key_b64"], expected_length=32)
                Ed25519PublicKey.from_public_bytes(old_public_key).verify(old_signature, message)
                Ed25519PublicKey.from_public_bytes(new_public_key).verify(new_signature, message)
            except (InvalidSignature, ValueError):
                raise PermissionError("Both device keys must prove possession") from None
            used = connection.execute(
                """
                UPDATE device_key_rotation_challenges SET used_at=?
                WHERE id=? AND device_id=? AND user_id=? AND used_at IS NULL
                """,
                (now.isoformat(), challenge_id, device_id, owner_id),
            )
            if used.rowcount != 1:
                raise ValueError("Device key rotation challenge already used")
            rotated = connection.execute(
                """
                UPDATE devices SET public_key_b64=?,public_key_fingerprint=?,last_seen_at=?
                WHERE id=? AND user_id=? AND status='active'
                """,
                (row["proposed_public_key_b64"],row["proposed_fingerprint"],
                 now.isoformat(),device_id,owner_id),
            )
            if rotated.rowcount != 1:
                raise ValueError("Device key rotation state changed")
            applied = connection.execute(
                """
                UPDATE device_key_rotation_challenges SET applied_at=?
                WHERE id=? AND used_at=? AND applied_at IS NULL
                """,
                (now.isoformat(),challenge_id,now.isoformat()),
            )
            if applied.rowcount != 1:
                raise ValueError("Device key rotation challenge already used")
            connection.execute(
                """
                UPDATE sessions SET revoked_at=?
                WHERE device_id=? AND user_id=? AND revoked_at IS NULL
                """,
                (now.isoformat(),device_id,owner_id),
            )
            connection.execute(
                """
                INSERT INTO device_security_events
                    (id,user_id,device_id,event_type,occurred_at,details_json)
                VALUES (?,?,?,'device.key_rotated',?,?)
                """,
                (
                    str(uuid.uuid4()),owner_id,device_id,now.isoformat(),
                    json.dumps({
                        "previous_fingerprint":row["public_key_fingerprint"],
                        "new_fingerprint":row["proposed_fingerprint"],
                    },separators=(",",":"),sort_keys=True),
                ),
            )
        return row["proposed_fingerprint"]


    def create_recovery_rotation_challenge(
        self,
        owner_id: str,
        device_id: str,
        recovery_code: str,
        new_public_key_b64: str,
    ) -> dict:
        """Issue a one-use recovery challenge after validating an unused code."""
        if (
            not isinstance(recovery_code, str)
            or not recovery_code.isascii()
            or not 20 <= len(recovery_code) <= 128
        ):
            raise ValueError("Invalid recovery code")
        new_public_key = _b64decode(new_public_key_b64, expected_length=32)
        canonical_key = base64.b64encode(new_public_key).decode("ascii")
        new_fingerprint = hashlib.sha256(new_public_key).hexdigest()
        code_hash = hashlib.sha256(recovery_code.encode("ascii")).hexdigest()
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(32)
        now = _now()
        expires_text = (now + timedelta(minutes=5)).isoformat()

        with self._transaction():
            connection = self.database.connect()
            self._lock_owner_device(connection, owner_id, device_id)
            device = connection.execute(
                """
                SELECT d.public_key_fingerprint
                FROM devices d
                JOIN users u ON u.id=d.user_id
                WHERE d.id=? AND d.user_id=? AND d.status='active'
                  AND d.public_key_b64 IS NOT NULL AND u.deleted_at IS NULL
                """,
                (device_id, owner_id),
            ).fetchone()
            if device is None:
                raise LookupError("Recovery target not found")
            if secrets.compare_digest(
                device["public_key_fingerprint"], new_fingerprint
            ):
                raise ValueError("Replacement key must differ from the current key")

            recovery = connection.execute(
                """
                SELECT id FROM webauthn_recovery_codes
                WHERE user_id=? AND code_hash=? AND used_at IS NULL
                """,
                (owner_id, code_hash),
            ).fetchone()
            if recovery is None:
                raise LookupError("Recovery target not found")

            cutoff = (now - timedelta(minutes=5)).isoformat()
            recent = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM device_key_rotation_challenges
                WHERE device_id=? AND user_id=? AND created_at>?
                """,
                (device_id, owner_id, cutoff),
            ).fetchone()["total"]
            if recent >= 5:
                raise PermissionError("Device recovery rate limit exceeded")

            connection.execute(
                """
                DELETE FROM device_key_rotation_challenges
                WHERE expires_at<=? OR (used_at IS NOT NULL AND used_at<=?)
                """,
                (now.isoformat(), (now - timedelta(days=1)).isoformat()),
            )
            connection.execute(
                """
                INSERT INTO device_key_rotation_challenges (
                    id,device_id,user_id,nonce_hash,previous_fingerprint,
                    proposed_public_key_b64,proposed_fingerprint,expires_at,
                    created_at,recovery_code_id
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    challenge_id, device_id, owner_id,
                    hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                    device["public_key_fingerprint"], canonical_key,
                    new_fingerprint, expires_text, now.isoformat(),
                    recovery["id"],
                ),
            )

        message = (
            f"AIBRAIN_DEVICE_KEY_RECOVERY_V1\n{challenge_id}\n{device_id}\n"
            f"{owner_id}\n{expires_text}\n{nonce}\n{new_fingerprint}"
        ).encode("utf-8")
        return {
            "challenge_id": challenge_id,
            "device_id": device_id,
            "nonce": nonce,
            "expires_at": expires_text,
            "new_public_key_fingerprint": new_fingerprint,
            "message_b64": base64.b64encode(message).decode("ascii"),
        }

    def verify_and_recover_key(
        self,
        device_id: str,
        challenge_id: str,
        nonce: str,
        new_signature_b64: str,
    ) -> str:
        """Consume one recovery code and rotate a lost device key atomically."""
        new_signature = _b64decode(new_signature_b64, expected_length=64)
        if (
            not isinstance(nonce, str)
            or not nonce.isascii()
            or not 20 <= len(nonce) <= 128
        ):
            raise ValueError("Invalid challenge nonce")
        now = _now()

        with self._transaction():
            connection = self.database.connect()
            owner_row = connection.execute(
                "SELECT user_id FROM device_key_rotation_challenges WHERE id=? AND device_id=? AND recovery_code_id IS NOT NULL",
                (challenge_id, device_id),
            ).fetchone()
            if owner_row is None:
                raise LookupError("Device recovery challenge not found")
            owner_id = owner_row["user_id"]
            self._lock_owner_device(connection, owner_id, device_id)
            recovery_row_lock = (
                "FOR UPDATE OF r"
                if getattr(self.database, "dialect", None) == "postgresql"
                else ""
            )
            row = connection.execute(
                f"""
                SELECT c.user_id,c.nonce_hash,c.expires_at,c.used_at,c.applied_at,
                       c.previous_fingerprint,c.proposed_public_key_b64,
                       c.proposed_fingerprint,c.recovery_code_id,
                       d.public_key_fingerprint,r.used_at AS recovery_used_at
                FROM device_key_rotation_challenges c
                JOIN devices d ON d.id=c.device_id AND d.user_id=c.user_id
                JOIN users u ON u.id=c.user_id
                JOIN webauthn_recovery_codes r
                  ON r.id=c.recovery_code_id AND r.user_id=c.user_id
                WHERE c.id=? AND c.device_id=? AND c.recovery_code_id IS NOT NULL
                  AND d.status='active' AND u.deleted_at IS NULL
                {recovery_row_lock}
                """,
                (challenge_id, device_id),
            ).fetchone()
            if row is None:
                raise LookupError("Device recovery challenge not found")
            if row["used_at"] is not None or row["applied_at"] is not None:
                raise ValueError("Device recovery challenge already used")
            if row["recovery_used_at"] is not None:
                raise ValueError("Recovery code has already been used")
            if not secrets.compare_digest(
                row["previous_fingerprint"], row["public_key_fingerprint"]
            ):
                raise ValueError("Device key changed after recovery challenge issuance")
            if datetime.fromisoformat(row["expires_at"]) <= now:
                raise ValueError("Device recovery challenge expired")
            nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
            if not secrets.compare_digest(nonce_hash, row["nonce_hash"]):
                raise ValueError("Device recovery nonce mismatch")

            message = (
                f"AIBRAIN_DEVICE_KEY_RECOVERY_V1\n{challenge_id}\n{device_id}\n"
                f"{row['user_id']}\n{row['expires_at']}\n{nonce}\n"
                f"{row['proposed_fingerprint']}"
            ).encode("utf-8")
            try:
                replacement_key = _b64decode(
                    row["proposed_public_key_b64"], expected_length=32
                )
                Ed25519PublicKey.from_public_bytes(replacement_key).verify(
                    new_signature, message
                )
            except (InvalidSignature, ValueError):
                raise PermissionError(
                    "Replacement device key proof was rejected"
                ) from None

            consumed_code = connection.execute(
                """
                UPDATE webauthn_recovery_codes SET used_at=?
                WHERE id=? AND user_id=? AND used_at IS NULL
                """,
                (now.isoformat(), row["recovery_code_id"], row["user_id"]),
            )
            if consumed_code.rowcount != 1:
                raise ValueError("Recovery code has already been used")

            consumed_challenge = connection.execute(
                """
                UPDATE device_key_rotation_challenges SET used_at=?
                WHERE id=? AND device_id=? AND user_id=? AND used_at IS NULL
                """,
                (now.isoformat(), challenge_id, device_id, row["user_id"]),
            )
            if consumed_challenge.rowcount != 1:
                raise ValueError("Device recovery challenge already used")

            recovered = connection.execute(
                """
                UPDATE devices
                SET public_key_b64=?,public_key_fingerprint=?,last_seen_at=?
                WHERE id=? AND user_id=? AND status='active'
                """,
                (
                    row["proposed_public_key_b64"],
                    row["proposed_fingerprint"],
                    now.isoformat(),
                    device_id,
                    row["user_id"],
                ),
            )
            if recovered.rowcount != 1:
                raise ValueError("Device recovery state changed")
            applied = connection.execute(
                """
                UPDATE device_key_rotation_challenges SET applied_at=?
                WHERE id=? AND used_at=? AND applied_at IS NULL
                """,
                (now.isoformat(), challenge_id, now.isoformat()),
            )
            if applied.rowcount != 1:
                raise ValueError("Device recovery challenge already used")
            connection.execute(
                """
                UPDATE sessions SET revoked_at=?
                WHERE device_id=? AND user_id=? AND revoked_at IS NULL
                """,
                (now.isoformat(), device_id, row["user_id"]),
            )
            connection.execute(
                """
                INSERT INTO device_security_events
                    (id,user_id,device_id,event_type,occurred_at,details_json)
                VALUES (?,?,?,'device.key_rotated',?,?)
                """,
                (
                    str(uuid.uuid4()),
                    row["user_id"],
                    device_id,
                    now.isoformat(),
                    json.dumps(
                        {
                            "previous_fingerprint": row["public_key_fingerprint"],
                            "new_fingerprint": row["proposed_fingerprint"],
                            "recovery": True,
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                ),
            )
        return row["proposed_fingerprint"]
