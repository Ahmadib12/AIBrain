import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from backend.app.persistence.contracts import DatabaseProtocol


_DUMMY_PASSWORD_SALT = "aibrain-dummy-password-salt"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_email_unique_violation(error: BaseException) -> bool:
    """Recognize only the users.email uniqueness constraint across supported drivers."""
    sqlstate = getattr(error, "sqlstate", None)
    diagnostic = getattr(error, "diag", None)
    constraint_name = getattr(diagnostic, "constraint_name", None)
    if sqlstate == "23505":
        return constraint_name == "users_email_key"

    # sqlite3.IntegrityError exposes no structured constraint metadata.
    message = str(error).lower()
    return message in {
        "unique constraint failed: users.email",
        "unique constraint failed: users.email",
    }


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
        database: DatabaseProtocol,
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
            try:
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
            except Exception as exc:
                # The preflight SELECT improves the common path, but the
                # database uniqueness constraint is the concurrency arbiter.
                if _is_email_unique_violation(exc):
                    raise ValueError("Email is already registered") from exc
                raise
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

    def create_session(
        self, user_id: str, *, device_id: str | None = None,
        auth_method: str | None = None,
    ) -> tuple[dict, str]:
        """Create an account session, optionally bound to an active owned device."""
        if auth_method is None:
            auth_method = "device_proof" if device_id is not None else "account"
        if auth_method not in {"account", "device_proof", "device_login"}:
            raise ValueError("Unsupported session authentication method")
        if device_id is None and auth_method != "account":
            raise ValueError("Device authentication method requires a device")
        if device_id is not None and auth_method == "account":
            raise ValueError("Device-bound session requires device authentication")

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

            if device_id is not None:
                active_device = connection.execute(
                    """
                    SELECT id FROM devices
                    WHERE id = ? AND user_id = ? AND status = 'active'
                    """,
                    (device_id, user_id),
                ).fetchone()
                if active_device is None:
                    raise LookupError("Active owned device not found")

            connection.execute(
                """
                INSERT INTO sessions (
                    token_hash, user_id, expires_at, created_at, device_id, auth_method
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_hash, user_id, expires, now, device_id, auth_method),
            )

        user = self.get_user(user_id)
        if device_id is not None:
            user["device_id"] = device_id
        return user, token

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
                   s.expires_at, s.device_id, d.status AS device_status
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            LEFT JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
            WHERE s.token_hash = ?
              AND s.revoked_at IS NULL
              AND u.deleted_at IS NULL
              AND (s.device_id IS NULL OR d.status = 'active')
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            raise LookupError("Session not found")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            raise LookupError("Session expired")
        user = {
            "id": row["id"],
            "email": row["email"],
            "display_name": row["display_name"],
            "created_at": row["created_at"],
        }
        if row["device_id"] is not None:
            user["device_id"] = row["device_id"]
        return user

    def list_owned_sessions(self, owner_id: str, current_token: str) -> tuple[dict, ...]:
        """List valid sessions for one owner without exposing authentication material."""
        token_hash = hashlib.sha256(current_token.encode("utf-8")).hexdigest()
        now = _utc_now()
        rows = self.database.connect().execute(
            """
            SELECT s.audit_ref, s.device_id, s.auth_method, s.created_at, s.expires_at,
                   s.token_hash
            FROM sessions s
            LEFT JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
            WHERE s.user_id = ?
              AND s.revoked_at IS NULL
              AND s.expires_at > ?
              AND (s.device_id IS NULL OR d.status = 'active')
            ORDER BY s.created_at DESC, s.audit_ref DESC
            """,
            (owner_id, now),
        ).fetchall()
        return tuple(
            {
                "session_ref": row["audit_ref"],
                "device_id": row["device_id"],
                "auth_method": row["auth_method"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "is_current": secrets.compare_digest(row["token_hash"], token_hash),
            }
            for row in rows
        )

    def revoke_owned_session(
        self,
        owner_id: str,
        session_ref: str,
        current_token: str,
    ) -> bool:
        """Revoke one active owned session; return False for any unavailable target."""
        current_hash = hashlib.sha256(current_token.encode("utf-8")).hexdigest()
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT s.token_hash
                FROM sessions s
                LEFT JOIN devices d ON d.id = s.device_id AND d.user_id = s.user_id
                WHERE s.user_id = ?
                  AND s.audit_ref = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > ?
                  AND (s.device_id IS NULL OR d.status = 'active')
                """,
                (owner_id, session_ref, now),
            ).fetchone()
            if row is None:
                return False
            if secrets.compare_digest(row["token_hash"], current_hash):
                raise ValueError("The current session must be ended through logout")
            cursor = connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND audit_ref = ? AND revoked_at IS NULL
                """,
                (now, owner_id, session_ref),
            )
            return cursor.rowcount == 1

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

            # Remove integration audit and consent state after owner tombstoning.
            connection.execute(
                "DELETE FROM devices WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM integration_connection_events WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM integration_connection_grants WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM integration_connections WHERE user_id = ?",
                (user_id,),
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
                "DELETE FROM agents WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM learning_evaluations WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM learning_adaptation_events WHERE user_id = ?",
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
