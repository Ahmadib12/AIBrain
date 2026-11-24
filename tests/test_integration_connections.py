import sqlite3

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.identity import IdentityRepository
from backend.app.persistence.integration_connections import IntegrationConnectionRepository


@pytest.fixture
def state():
    database = Database("sqlite:///:memory:")
    identity = IdentityRepository(database, session_ttl_seconds=3600)
    owner = identity.register(
        email="integration-owner@example.com",
        password="safe-password-123",
        display_name="Owner",
    )
    other = identity.register(
        email="integration-other@example.com",
        password="safe-password-123",
        display_name="Other",
    )
    repository = IntegrationConnectionRepository(database)
    try:
        yield database, identity, owner["id"], other["id"], repository
    finally:
        database.shutdown()


def test_owner_consent_creates_pending_connection_and_exact_pending_grants(state):
    _, _, owner_id, _, repository = state
    connection = repository.create_pending(
        owner_id, "calendar", ["calendar.events.read"],
        consent_version="v1",
    )
    assert connection["status"] == "pending_verification"
    assert connection["consent_version"] == "v1"
    assert connection["grants"] == [{
        "scope": "calendar.events.read",
        "status": "pending",
        "expires_at": None,
        "revoked_at": None,
    }]
    assert "secret_ref" not in connection
    assert repository.has_active_grants(
        owner_id, connection["id"], "calendar", ("calendar.events.read",)
    ) is False


def test_connection_records_are_owner_scoped(state):
    _, _, owner_id, other_id, repository = state
    connection = repository.create_pending(
        owner_id, "calendar", ["calendar.events.read"],
        consent_version="v1",
    )
    with pytest.raises(LookupError):
        repository.get(other_id, connection["id"])
    assert repository.list_for_owner(other_id) == []


def test_revocation_blocks_grants_and_is_audited(state):
    database, _, owner_id, _, repository = state
    connection = repository.create_pending(
        owner_id, "calendar", ["calendar.events.read"],
        consent_version="v1",
    )
    revoked = repository.revoke(owner_id, connection["id"])
    assert revoked["status"] == "revoked"
    assert revoked["grants"][0]["status"] == "revoked"
    assert repository.has_active_grants(
        owner_id, connection["id"], "calendar", ("calendar.events.read",)
    ) is False
    event = database.connect().execute(
        """SELECT 1 FROM integration_connection_events
           WHERE connection_id=? AND event_type='owner_revoked_connection'""",
        (connection["id"],),
    ).fetchone()
    assert event is not None


def test_disconnect_is_terminal_for_grants(state):
    _, _, owner_id, _, repository = state
    connection = repository.create_pending(
        owner_id, "calendar", ["calendar.events.read"],
        consent_version="v1",
    )
    disconnected = repository.disconnect(owner_id, connection["id"])
    assert disconnected["status"] == "disconnected"
    assert disconnected["grants"][0]["status"] == "revoked"


def test_invalid_or_duplicate_scope_consent_is_rejected(state):
    _, _, owner_id, _, repository = state
    with pytest.raises(ValueError):
        repository.create_pending(owner_id, "calendar", [], consent_version="v1")
    with pytest.raises(ValueError):
        repository.create_pending(
            owner_id, "calendar", ["calendar.events.read"] * 2,
            consent_version="v1",
        )


def test_account_erasure_removes_integration_consent_and_audit_state(state):
    database, identity, owner_id, _, repository = state
    connection = repository.create_pending(
        owner_id, "calendar", ["calendar.events.read"],
        consent_version="v1",
    )
    identity.delete_user(owner_id)
    for table in (
        "integration_connection_events",
        "integration_connection_grants",
        "integration_connections",
    ):
        count = database.connect().execute(
            f"SELECT COUNT(*) FROM {table} WHERE user_id=?",
            (owner_id,),
        ).fetchone()[0]
        assert count == 0

def test_database_rejects_unverified_connection_activation(state):
    database, _, owner_id, _, repository = state
    connection = repository.create_pending(
        owner_id, "calendar", ["calendar.events.read"], consent_version="v1"
    )
    with pytest.raises(sqlite3.IntegrityError, match="verified vault credentials"):
        database.connect().execute(
            "UPDATE integration_connections SET status='active' WHERE id=?",
            (connection["id"],),
        )


def test_database_rejects_active_grant_without_active_connection(state):
    database, _, owner_id, _, repository = state
    connection = repository.create_pending(
        owner_id, "calendar", ["calendar.events.read"], consent_version="v1"
    )
    with pytest.raises(sqlite3.IntegrityError, match="active connection"):
        database.connect().execute(
            "UPDATE integration_connection_grants SET status='active' WHERE connection_id=? AND user_id=?",
            (connection["id"], owner_id),
        )

def test_invalid_scope_identifier_is_rejected_at_repository_boundary(state):
    _, _, owner_id, _, repository = state
    with pytest.raises(ValueError, match="Requested scope is invalid"):
        repository.create_pending(
            owner_id, "calendar", ["../secrets"], consent_version="v1"
        )
