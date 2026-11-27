"""Owner-scoped integration connection consent and grant lifecycle.

This repository intentionally stores no provider token material. A connection
cannot become active through public API input: trusted provider verification
and a separately managed encrypted secret store are required first.
"""
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

from backend.app.persistence.contracts import DatabaseProtocol

_SCOPE_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{1,95}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IntegrationConnectionRepository:
    def __init__(self, database: DatabaseProtocol) -> None:
        self.database = database

    def create_pending(
        self,
        user_id: str,
        integration_id: str,
        requested_scopes: list[str],
        *,
        consent_version: str,
    ) -> dict:
        if not isinstance(integration_id, str) or not integration_id.strip():
            raise ValueError("Integration ID is invalid")
        if not isinstance(consent_version, str) or not consent_version.strip() or len(consent_version) > 64:
            raise ValueError("Consent version is invalid")
        if not isinstance(requested_scopes, list) or not requested_scopes:
            raise ValueError("At least one scope must be explicitly requested")
        if any(not isinstance(scope, str) or not _SCOPE_PATTERN.fullmatch(scope) for scope in requested_scopes):
            raise ValueError("Requested scope is invalid")
        if len(requested_scopes) != len(set(requested_scopes)):
            raise ValueError("Requested scopes must be unique")

        now = _now()
        verification_expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=15)
        ).isoformat()
        connection_id = str(uuid.uuid4())
        with self.database.transaction(immediate=True):
            owner = self.database.connect().execute(
                "SELECT id FROM users WHERE id=? AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
            if owner is None:
                raise LookupError("User not found")
            self.database.connect().execute(
                """INSERT INTO integration_connections
                   (id,user_id,integration_id,status,consent_version,consented_at,
                    expires_at,created_at,updated_at)
                   VALUES (?,?,?,'pending_verification',?,?,?,?,?)""",
                (connection_id, user_id, integration_id, consent_version, now,
                 verification_expires_at, now, now),
            )
            for scope in requested_scopes:
                self.database.connect().execute(
                    """INSERT INTO integration_connection_grants
                       (id,user_id,connection_id,scope,status,created_at)
                       VALUES (?,?,?,?,'pending',?)""",
                    (str(uuid.uuid4()), user_id, connection_id, scope, now),
                )
            self._event(user_id, connection_id, "owner_consent_recorded", {
                "integration_id": integration_id,
                "requested_scopes": sorted(requested_scopes),
                "consent_version": consent_version,
            })
        return self.get(user_id, connection_id)

    def _event(self, user_id: str, connection_id: str, event_type: str, details: dict) -> None:
        self.database.connect().execute(
            """INSERT INTO integration_connection_events
               (id,user_id,connection_id,event_type,details_json,created_at)
               VALUES (?,?,?,?,?,?)""",
            (str(uuid.uuid4()), user_id, connection_id,
             event_type, json.dumps(details, sort_keys=True, separators=(",", ":")), _now()),
        )

    def get(self, user_id: str, connection_id: str) -> dict:
        row = self.database.connect().execute(
            """SELECT id,integration_id,status,consent_version,consented_at,
                      verified_at,expires_at,created_at,updated_at
               FROM integration_connections WHERE id=? AND user_id=?""",
            (connection_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Integration connection not found")
        item = dict(row)
        grants = self.database.connect().execute(
            """SELECT scope,status,expires_at,revoked_at
               FROM integration_connection_grants
               WHERE connection_id=? AND user_id=? ORDER BY scope""",
            (connection_id, user_id),
        ).fetchall()
        item["grants"] = [dict(grant) for grant in grants]
        return item

    def list_for_owner(self, user_id: str) -> list[dict]:
        rows = self.database.connect().execute(
            """SELECT id FROM integration_connections
               WHERE user_id=? ORDER BY created_at DESC,id""",
            (user_id,),
        ).fetchall()
        return [self.get(user_id, row["id"]) for row in rows]

    def revoke(self, user_id: str, connection_id: str) -> dict:
        now = _now()
        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                "SELECT status FROM integration_connections WHERE id=? AND user_id=?",
                (connection_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("Integration connection not found")
            if row["status"] not in {"revoked", "disconnected"}:
                self.database.connect().execute(
                    """UPDATE integration_connections
                       SET status='revoked',updated_at=? WHERE id=? AND user_id=?""",
                    (now, connection_id, user_id),
                )
                self.database.connect().execute(
                    """UPDATE integration_connection_grants
                       SET status='revoked',revoked_at=COALESCE(revoked_at,?)
                       WHERE connection_id=? AND user_id=?""",
                    (now, connection_id, user_id),
                )
                self._event(user_id, connection_id, "owner_revoked_connection", {})
        return self.get(user_id, connection_id)

    def disconnect(self, user_id: str, connection_id: str) -> dict:
        now = _now()
        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                "SELECT status FROM integration_connections WHERE id=? AND user_id=?",
                (connection_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("Integration connection not found")
            if row["status"] != "disconnected":
                self.database.connect().execute(
                    """UPDATE integration_connections
                       SET status='disconnected',updated_at=? WHERE id=? AND user_id=?""",
                    (now, connection_id, user_id),
                )
                self.database.connect().execute(
                    """UPDATE integration_connection_grants
                       SET status='revoked',revoked_at=COALESCE(revoked_at,?)
                       WHERE connection_id=? AND user_id=?""",
                    (now, connection_id, user_id),
                )
                self._event(user_id, connection_id, "owner_disconnected", {})
        return self.get(user_id, connection_id)

    def has_active_grants(
        self, user_id: str, connection_id: str, integration_id: str,
        required_scopes: tuple[str, ...],
    ) -> bool:
        row = self.database.connect().execute(
            """SELECT c.status,c.expires_at FROM integration_connections c
               WHERE c.id=? AND c.user_id=? AND c.integration_id=?""",
            (connection_id, user_id, integration_id),
        ).fetchone()
        if row is None or row["status"] != "active":
            return False
        now = _now()
        if row["expires_at"] is not None and row["expires_at"] <= now:
            return False
        for scope in required_scopes:
            grant = self.database.connect().execute(
                """SELECT 1 FROM integration_connection_grants
                   WHERE connection_id=? AND user_id=? AND scope=?
                     AND status='active' AND revoked_at IS NULL
                     AND (expires_at IS NULL OR expires_at>?)""",
                (connection_id, user_id, scope, now),
            ).fetchone()
            if grant is None:
                return False
        return True


    def activate_verified(
        self, user_id: str, connection_id: str, *, secret_ref: str,
        verifier_id: str, provider_subject_fingerprint: str,
        granted_scopes: tuple[str, ...], expires_at: str | None,
    ) -> dict:
        """Activate only after the trusted verifier and vault have succeeded."""
        now = _now()
        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                """SELECT integration_id,status,expires_at FROM integration_connections
                   WHERE id=? AND user_id=?""",
                (connection_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("Integration connection not found")
            if row["status"] != "pending_verification":
                raise PermissionError("Connection is no longer pending verification")
            if row["expires_at"] is None or row["expires_at"] <= now:
                raise PermissionError("Pending provider verification has expired")
            if expires_at is None or expires_at <= now:
                raise PermissionError("Verified provider credentials are expired")
            pending = self.database.connect().execute(
                """SELECT scope FROM integration_connection_grants
                   WHERE connection_id=? AND user_id=? AND status='pending'
                   ORDER BY scope""",
                (connection_id, user_id),
            ).fetchall()
            expected = tuple(item["scope"] for item in pending)
            if tuple(sorted(granted_scopes)) != expected:
                raise PermissionError("Provider scopes do not match owner consent")
            self.database.connect().execute(
                """UPDATE integration_connections
                   SET status='active',verified_at=?,expires_at=?,secret_ref=?,updated_at=?
                   WHERE id=? AND user_id=? AND status='pending_verification'""",
                (now, expires_at, secret_ref, now, connection_id, user_id),
            )
            self.database.connect().execute(
                """UPDATE integration_connection_grants
                   SET status='active',expires_at=?
                   WHERE connection_id=? AND user_id=? AND status='pending'""",
                (expires_at, connection_id, user_id),
            )
            self._event(user_id, connection_id, "provider_connection_verified", {
                "verifier_id": verifier_id,
                "provider_subject_fingerprint": provider_subject_fingerprint,
                "granted_scopes": list(expected),
                "expires_at": expires_at,
            })
        return self.get(user_id, connection_id)

    def expire_pending(self, user_id: str, connection_id: str) -> None:
        now = _now()
        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                """SELECT status FROM integration_connections
                   WHERE id=? AND user_id=?""",
                (connection_id, user_id),
            ).fetchone()
            if row is None or row["status"] != "pending_verification":
                return
            self.database.connect().execute(
                """UPDATE integration_connections SET status='expired',updated_at=?
                   WHERE id=? AND user_id=? AND status='pending_verification'""",
                (now, connection_id, user_id),
            )
            self.database.connect().execute(
                """UPDATE integration_connection_grants SET status='expired'
                   WHERE connection_id=? AND user_id=? AND status='pending'""",
                (connection_id, user_id),
            )
            self._event(user_id, connection_id, "pending_connection_expired", {})

    def expire_due(self) -> int:
        """Expire connections and grants atomically; terminal connections lose ciphertext."""
        now = _now()
        changed = 0
        rows = self.database.connect().execute(
            """SELECT id,user_id,status FROM integration_connections
               WHERE status IN ('pending_verification','active')
                 AND expires_at IS NOT NULL AND expires_at<=?""",
            (now,),
        ).fetchall()
        for row in rows:
            with self.database.transaction(immediate=True):
                current = self.database.connect().execute(
                    """SELECT status,expires_at FROM integration_connections
                       WHERE id=? AND user_id=?""",
                    (row["id"], row["user_id"]),
                ).fetchone()
                if (
                    current is None or current["status"] not in
                    {"pending_verification", "active"}
                    or current["expires_at"] is None
                    or current["expires_at"] > now
                ):
                    continue
                self.database.connect().execute(
                    """UPDATE integration_connections SET status='expired',updated_at=?
                       WHERE id=? AND user_id=?""",
                    (now, row["id"], row["user_id"]),
                )
                self.database.connect().execute(
                    """UPDATE integration_connection_grants
                       SET status='expired' WHERE connection_id=? AND user_id=?
                         AND status IN ('pending','active')""",
                    (row["id"], row["user_id"]),
                )
                self._event(row["user_id"], row["id"], "connection_expired", {})
                changed += 1

        grant_rows = self.database.connect().execute(
            """SELECT id,user_id,connection_id FROM integration_connection_grants
               WHERE status='active' AND expires_at IS NOT NULL AND expires_at<=?""",
            (now,),
        ).fetchall()
        for grant in grant_rows:
            with self.database.transaction(immediate=True):
                cursor = self.database.connect().execute(
                    """UPDATE integration_connection_grants SET status='expired'
                       WHERE id=? AND user_id=? AND status='active' AND expires_at<=?""",
                    (grant["id"], grant["user_id"], now),
                )
                if cursor.rowcount:
                    self._event(grant["user_id"], grant["connection_id"], "scope_grant_expired", {
                        "grant_id": grant["id"],
                    })
                    changed += 1
        # If every owner-granted scope has expired, expire the connection too
        # so the terminal-state trigger destroys its encrypted credentials.
        inactive = self.database.connect().execute(
            """SELECT c.id,c.user_id FROM integration_connections c
               WHERE c.status='active'
                 AND NOT EXISTS (
                   SELECT 1 FROM integration_connection_grants g
                   WHERE g.connection_id=c.id AND g.user_id=c.user_id
                     AND g.status='active' AND g.revoked_at IS NULL
                     AND (g.expires_at IS NULL OR g.expires_at>?)
                 )""",
            (now,),
        ).fetchall()
        for row in inactive:
            with self.database.transaction(immediate=True):
                cursor = self.database.connect().execute(
                    """UPDATE integration_connections SET status='expired',updated_at=?
                       WHERE id=? AND user_id=? AND status='active'""",
                    (now, row["id"], row["user_id"]),
                )
                if cursor.rowcount:
                    self.database.connect().execute(
                        """UPDATE integration_connection_grants SET status='expired'
                           WHERE connection_id=? AND user_id=? AND status='active'""",
                        (row["id"], row["user_id"]),
                    )
                    self._event(row["user_id"], row["id"], "connection_expired_no_active_grants", {})
                    changed += 1
        return changed


    def latest_provider_subject(self, user_id: str, connection_id: str) -> str | None:
        row = self.database.connect().execute(
            """SELECT details_json FROM integration_connection_events
               WHERE user_id=? AND connection_id=?
                 AND event_type IN ('provider_connection_verified','provider_credentials_rotated')
               ORDER BY created_at DESC,id DESC LIMIT 1""",
            (user_id, connection_id),
        ).fetchone()
        if row is None:
            return None
        details = json.loads(row["details_json"])
        return details.get("provider_subject_fingerprint")

    def record_credential_rotation(
        self, user_id: str, connection_id: str, *,
        verifier_id: str, provider_subject_fingerprint: str,
        expires_at: str | None,
    ) -> dict:
        now = _now()
        with self.database.transaction(immediate=True):
            row = self.database.connect().execute(
                """SELECT c.integration_id,c.status,s.key_version
                   FROM integration_connections c
                   JOIN integration_secrets s
                     ON s.secret_ref=c.secret_ref AND s.connection_id=c.id
                    AND s.user_id=c.user_id AND s.integration_id=c.integration_id
                   WHERE c.id=? AND c.user_id=?""",
                (connection_id, user_id),
            ).fetchone()
            if row is None or row["status"] != "active":
                raise PermissionError("Active verified credentials are required for rotation")
            if expires_at is None or expires_at <= now:
                raise PermissionError("Rotated provider credentials are expired")
            self.database.connect().execute(
                """UPDATE integration_connections SET expires_at=?,updated_at=?
                   WHERE id=? AND user_id=? AND status='active'""",
                (expires_at, now, connection_id, user_id),
            )
            self.database.connect().execute(
                """UPDATE integration_connection_grants SET expires_at=?
                   WHERE connection_id=? AND user_id=? AND status='active'""",
                (expires_at, connection_id, user_id),
            )
            self._event(user_id, connection_id, "provider_credentials_rotated", {
                "verifier_id": verifier_id,
                "provider_subject_fingerprint": provider_subject_fingerprint,
                "expires_at": expires_at,
                "key_version": row["key_version"],
            })
        return self.get(user_id, connection_id)
