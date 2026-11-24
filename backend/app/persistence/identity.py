import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from backend.app.persistence.database import Database


_DUMMY_PASSWORD_SALT = "aibrain-dummy-password-salt"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("ascii"),
        200_000,
    ).hex()


class IdentityRepository:
    def __init__(
        self,
        database: Database,
        *,
        session_ttl_seconds: int,
    ) -> None:
        self.database = database
        self.session_ttl_seconds = session_ttl_seconds

    def register(
        self,
        *,
        email: str,
        password: str,
        display_name: str | None,
    ) -> dict:
        normalized = email.strip().lower()
        if len(normalized) > 320 or "@" not in normalized:
            raise ValueError("Invalid email")
        if len(password) < 8 or len(password) > 128:
            raise ValueError("Password must contain 8 to 128 characters")

        with self.database.transaction():
            exists = self.database.connect().execute(
                "SELECT id FROM users WHERE email = ?",
                (normalized,),
            ).fetchone()
            if exists is not None:
                raise ValueError("Email is already registered")

            user_id = str(uuid.uuid4())
            salt = secrets.token_hex(16)
            password_hash = _hash_password(password, salt)
            now = _utc_now()
            self.database.connect().execute(
                "INSERT INTO users "
                "(id, email, password_salt, password_hash, display_name, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user_id,
                    normalized,
                    salt,
                    password_hash,
                    display_name,
                    now,
                ),
            )
        return self.get_user(user_id)

    def verify_password(
        self,
        *,
        user_id: str,
        password: str,
    ) -> bool:
        row = self.database.connect().execute(
            "SELECT password_salt, password_hash "
            "FROM users WHERE id = ? AND deleted_at IS NULL",
            (user_id,),
        ).fetchone()

        if row is None:
            _hash_password(password, _DUMMY_PASSWORD_SALT)
            return False

        candidate = _hash_password(password, row["password_salt"])
        return secrets.compare_digest(candidate, row["password_hash"])

    def authenticate(
        self,
        *,
        email: str,
        password: str,
    ) -> tuple[dict, str]:
        normalized = email.strip().lower()
        row = self.database.connect().execute(
            "SELECT * FROM users WHERE email = ? AND deleted_at IS NULL",
            (normalized,),
        ).fetchone()
        if row is None:
            _hash_password(password, _DUMMY_PASSWORD_SALT)
            raise ValueError("Invalid email or password")
        candidate = _hash_password(password, row["password_salt"])
        if not secrets.compare_digest(candidate, row["password_hash"]):
            raise ValueError("Invalid email or password")

        return self.create_session(row["id"])

    def get_user_by_email(self, email: str) -> dict | None:
        """Return an active account for a normalized email address."""
        if not isinstance(email, str):
            return None

        row = self.database.connect().execute(
            """
            SELECT id, email, display_name, created_at
            FROM users
            WHERE email = ? AND deleted_at IS NULL
            """,
            (email.strip().lower(),),
        ).fetchone()

        return dict(row) if row is not None else None

    def create_session(self, user_id: str) -> tuple[dict, str]:
        """Create the standard bearer session after successful authentication."""
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        expires = (
            datetime.now(timezone.utc)
            + timedelta(seconds=self.session_ttl_seconds)
        ).isoformat()
        now = _utc_now()

        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            active_user = connection.execute(
                """
                SELECT id FROM users
                WHERE id = ? AND deleted_at IS NULL
                """,
                (user_id,),
            ).fetchone()

            if active_user is None:
                raise LookupError("User not found")

            connection.execute(
                """
                INSERT INTO sessions (
                    token_hash, user_id, expires_at, created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (token_hash, user_id, expires, now),
            )

        return self.get_user(user_id), token

    def get_user(self, user_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT id, email, display_name, created_at "
            "FROM users WHERE id = ? AND deleted_at IS NULL",
            (user_id,),
        ).fetchone()
        if row is None:
            raise LookupError("User not found")
        return dict(row)

    def resolve_token(self, token: str) -> dict:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = self.database.connect().execute(
            """
            SELECT u.id, u.email, u.display_name, u.created_at,
                   s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
              AND s.revoked_at IS NULL
              AND u.deleted_at IS NULL
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            raise LookupError("Session not found")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            raise LookupError("Session expired")
        return {
            "id": row["id"],
            "email": row["email"],
            "display_name": row["display_name"],
            "created_at": row["created_at"],
        }

    def revoke_token(self, token: str) -> bool:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "UPDATE sessions SET revoked_at = ? "
                "WHERE token_hash = ? AND revoked_at IS NULL",
                (_utc_now(), token_hash),
            )
        return cursor.rowcount == 1

    def cleanup_sessions(self) -> int:
        now = _utc_now()
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "DELETE FROM sessions "
                "WHERE expires_at <= ? OR revoked_at IS NOT NULL",
                (now,),
            )
        return cursor.rowcount

    def delete_user(self, user_id: str) -> None:
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()

            # Tombstone the account before erasing dependent rows. The
            # lookup-authorization ledger permits cascading deletion only
            # inside this explicit account-erasure lifecycle.
            connection.execute(
                "UPDATE users SET deleted_at = COALESCE(deleted_at, ?) WHERE id = ?",
                (now, user_id),
            )

            # Remove dependent authorization records before their parents.
            for table in (
                "tool_authorizations",
                "webauthn_challenges",
                "webauthn_recovery_codes",
                "webauthn_credentials",
            ):
                connection.execute(
                    f"DELETE FROM {table} WHERE user_id = ?",
                    (user_id,),
                )

            connection.execute(
                "DELETE FROM tool_requests WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM observations WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM adaptations WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM memory_items WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM memory_consents WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) "
                "WHERE user_id = ?",
                (now, user_id),
            )
            connection.execute(
                "UPDATE audit_events "
                "SET user_id = NULL, details_json = '{}' "
                "WHERE user_id = ?",
                (user_id,),
            )
