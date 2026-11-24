"""Owner-scoped integration connection consent and grant lifecycle.

This repository intentionally stores no provider token material. A connection
cannot become active through public API input: trusted provider verification
and a separately managed encrypted secret store are required first.
"""
import json
import uuid
from datetime import datetime, timezone

from backend.app.persistence.database import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IntegrationConnectionRepository:
    def __init__(self, database: Database) -> None:
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
        if any(not isinstance(scope, str) or not scope.strip() or len(scope) > 128 for scope in requested_scopes):
            raise ValueError("Requested scope is invalid")
        if len(requested_scopes) != len(set(requested_scopes)):
            raise ValueError("Requested scopes must be unique")

        now = _now()
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
                    created_at,updated_at)
                   VALUES (?,?,?,'pending_verification',?,?,?,?)""",
                (connection_id, user_id, integration_id, consent_version, now, now, now),
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
