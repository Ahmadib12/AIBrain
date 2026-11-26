import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.app_state import get_app_state
from backend.app.providers.local import LocalAIProvider
from backend.app.providers.schemas import ChatRequest
from backend.app.providers.errors import ProviderUnavailableError
from backend.app.intelligence.multimodal import MediaReference, Modality, StreamEvent
from backend.app.tools import ToolRisk
from backend.app.agli.interfaces import LanguageProcessingEngine


@pytest.fixture
def client():
    state = get_app_state()
    with state.database.transaction():
        state.database.connect().execute("DELETE FROM tool_requests")
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(client: TestClient, email: str) -> str:
    registered = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "safe-password-123",
            "display_name": "Test User",
        },
    )
    assert registered.status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "safe-password-123"},
    )
    assert login.status_code == 200
    return login.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def grant_memory_consent(client: TestClient, token: str) -> None:
    response = client.post(
        "/api/v1/personal/memory/consent",
        headers=auth_header(token),
        json={"retention_days": 365},
    )
    assert response.status_code == 200




def test_unknown_login_email_performs_dummy_password_hash() -> None:
    import backend.app.persistence.identity as identity_module

    state = get_app_state()
    state.identity.register(
        email="timing-test@example.com",
        password="safe-password-123",
        display_name="Timing Test",
    )

    original_hash = identity_module._hash_password
    salts = []

    def tracking_hash(password: str, salt: str) -> str:
        salts.append(salt)
        return original_hash(password, salt)

    identity_module._hash_password = tracking_hash
    try:
        with pytest.raises(ValueError, match="Invalid email or password"):
            state.identity.authenticate(
                email="timing-test@example.com",
                password="wrong-password",
            )

        with pytest.raises(ValueError, match="Invalid email or password"):
            state.identity.authenticate(
                email="unknown-timing-test@example.com",
                password="wrong-password",
            )
    finally:
        identity_module._hash_password = original_hash

    assert len(salts) == 2
    assert salts[0] != salts[1]
    assert salts[1] == identity_module._DUMMY_PASSWORD_SALT

def test_auth_registration_login_me_and_logout(client: TestClient) -> None:
    token = register_and_login(client, "foundation@example.com")

    me = client.get(
        "/api/v1/auth/me",
        headers=auth_header(token),
    )
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "foundation@example.com"

    logout = client.post(
        "/api/v1/auth/logout",
        headers=auth_header(token),
    )
    assert logout.status_code == 200

    after_logout = client.get(
        "/api/v1/auth/me",
        headers=auth_header(token),
    )
    assert after_logout.status_code == 401



def test_login_route_blocks_repeated_failed_attempts(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.app.api.v1.auth as auth_module
    from backend.app.auth.rate_limit import LoginRateLimiter

    monkeypatch.setattr(
        auth_module,
        "_login_rate_limiter",
        LoginRateLimiter(limit=2, window_seconds=60),
    )

    email = "rate-limit-test@example.com"

    first = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )
    second = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )
    third = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )

    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 429
    assert third.json()["error"]["code"] == "LOGIN_RATE_LIMITED"



def test_successful_login_resets_failed_attempts(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.app.api.v1.auth as auth_module
    from backend.app.auth.rate_limit import LoginRateLimiter

    monkeypatch.setattr(
        auth_module,
        "_login_rate_limiter",
        LoginRateLimiter(limit=2, window_seconds=60),
    )

    email = "reset-limit-test@example.com"
    register_and_login(client, email)

    failed = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )
    assert failed.status_code == 401

    successful = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "safe-password-123"},
    )
    assert successful.status_code == 200

    second_failed = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )
    third_failed = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )
    fourth_failed = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )

    assert second_failed.status_code == 401
    assert third_failed.status_code == 401
    assert fourth_failed.status_code == 429
    assert fourth_failed.json()["error"]["code"] == "LOGIN_RATE_LIMITED"




def test_memory_creation_requires_explicit_consent(client: TestClient) -> None:
    token = register_and_login(client, "no-memory-consent@example.com")
    response = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "preference",
            "key": "language",
            "value": "English",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "MEMORY_CONSENT_REQUIRED"
    assert client.get(
        "/api/v1/personal/memory",
        headers=auth_header(token),
    ).json() == []



def test_revoked_memory_consent_ledger_cannot_be_reactivated_or_rewritten(
    client: TestClient,
) -> None:
    import sqlite3

    token = register_and_login(client, "memory-consent-ledger@example.com")
    grant_memory_consent(client, token)
    state = get_app_state()
    user = state.identity.resolve_token(token)
    row = state.database.connect().execute(
        """
        SELECT id FROM memory_consents
        WHERE user_id = ? AND revoked_at IS NULL
        """,
        (user["id"],),
    ).fetchone()
    assert row is not None

    revoked = client.delete(
        "/api/v1/personal/memory/consent",
        headers=auth_header(token),
    )
    assert revoked.status_code == 200

    with pytest.raises(sqlite3.IntegrityError, match="revocation is immutable"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE memory_consents SET revoked_at = NULL WHERE id = ?",
                (row["id"],),
            )

    with pytest.raises(sqlite3.IntegrityError, match="policy is immutable"):
        with state.database.transaction():
            state.database.connect().execute(
                "UPDATE memory_consents SET retention_days = 30 WHERE id = ?",
                (row["id"],),
            )

    with pytest.raises(sqlite3.IntegrityError, match="may only be deleted"):
        with state.database.transaction():
            state.database.connect().execute(
                "DELETE FROM memory_consents WHERE id = ?",
                (row["id"],),
            )


def test_memory_consent_revocation_locks_old_records_and_new_consent_does_not_restore_them(
    client: TestClient,
) -> None:
    token = register_and_login(client, "memory-revocation@example.com")
    grant_memory_consent(client, token)
    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "preference",
            "key": "language",
            "value": "English",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    memory_id = created.json()["id"]

    revoked = client.delete(
        "/api/v1/personal/memory/consent",
        headers=auth_header(token),
    )
    assert revoked.status_code == 200
    assert revoked.json()["enabled"] is False
    assert revoked.json()["deleted_memories"] == 0
    # Revocation blocks assistant retrieval but does not hide owner-held data.
    owner_list = client.get(
        "/api/v1/personal/memory",
        headers=auth_header(token),
    )
    assert len(owner_list.json()) == 1
    assert owner_list.json()[0]["id"] == memory_id
    locked_search = client.post(
        "/api/v1/personal/memory/search",
        headers=auth_header(token),
        json={"query": "language"},
    )
    assert locked_search.status_code == 403
    owner_export = client.post(
        "/api/v1/personal/memory/export",
        headers=auth_header(token),
    )
    assert owner_export.status_code == 200
    assert owner_export.json()["memories"][0]["id"] == memory_id

    regranted = client.post(
        "/api/v1/personal/memory/consent",
        headers=auth_header(token),
        json={"retention_days": 365},
    )
    assert regranted.status_code == 200
    # A new consent does not adopt old records into model context.
    owner_list_after_regrant = client.get(
        "/api/v1/personal/memory",
        headers=auth_header(token),
    )
    assert [item["id"] for item in owner_list_after_regrant.json()] == [memory_id]
    search_after_regrant = client.post(
        "/api/v1/personal/memory/search",
        headers=auth_header(token),
        json={"query": "language"},
    )
    assert search_after_regrant.status_code == 200
    assert search_after_regrant.json()["matches"] == []

    # Explicitly editing/reaffirming this one record adopts it to the new consent.
    reaffirmed = client.patch(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token),
        json={
            "key": "language",
            "memory_type": "preference",
            "value": "English",
            "confidence": 1.0,
        },
    )
    assert reaffirmed.status_code == 200
    search_after_reaffirmation = client.post(
        "/api/v1/personal/memory/search",
        headers=auth_header(token),
        json={"query": "language"},
    )
    assert len(search_after_reaffirmation.json()["matches"]) == 1

    deleted = client.delete(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token),
    )
    assert deleted.status_code == 200


def test_memory_consent_purge_option_erases_all_consent_generations(
    client: TestClient,
) -> None:
    token = register_and_login(client, "memory-purge@example.com")
    grant_memory_consent(client, token)
    first = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "context",
            "key": "first-generation",
            "value": "old locked record",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    assert first.status_code == 200

    revoked_first = client.delete(
        "/api/v1/personal/memory/consent",
        headers=auth_header(token),
    )
    assert revoked_first.status_code == 200
    assert revoked_first.json()["deleted_memories"] == 0

    grant_memory_consent(client, token)
    second = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "context",
            "key": "second-generation",
            "value": "new active record",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    assert second.status_code == 200

    revoked = client.delete(
        "/api/v1/personal/memory/consent?purge_existing=true",
        headers=auth_header(token),
    )
    assert revoked.status_code == 200
    assert revoked.json()["deleted_memories"] == 2
    assert client.get(
        "/api/v1/personal/memory",
        headers=auth_header(token),
    ).json() == []


def test_memory_retention_policy_is_applied_to_existing_and_new_records(
    client: TestClient,
) -> None:
    token = register_and_login(client, "memory-retention@example.com")
    grant_memory_consent(client, token)
    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "goal",
            "key": "study",
            "value": "Learn Python",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    assert created.status_code == 200
    initial_expiry = created.json()["expires_at"]

    policy = client.patch(
        "/api/v1/personal/memory/consent/retention",
        headers=auth_header(token),
        json={"retention_days": 1},
    )
    assert policy.status_code == 200
    assert policy.json()["retention_days"] == 1

    listed = client.get(
        "/api/v1/personal/memory",
        headers=auth_header(token),
    )
    assert listed.status_code == 200
    shortened = listed.json()[0]["expires_at"]
    assert shortened != initial_expiry


def test_memory_search_and_context_are_owner_scoped_and_opt_in(client: TestClient) -> None:
    token_a = register_and_login(client, "memory-search-a@example.com")
    token_b = register_and_login(client, "memory-search-b@example.com")
    grant_memory_consent(client, token_a)
    grant_memory_consent(client, token_b)
    create_a = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token_a),
        json={
            "memory_type": "preference",
            "key": "preferred_language",
            "value": "English",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    create_b = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token_b),
        json={
            "memory_type": "preference",
            "key": "preferred_language",
            "value": "French",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    assert create_a.status_code == 200
    assert create_b.status_code == 200

    search = client.post(
        "/api/v1/personal/memory/search",
        headers=auth_header(token_a),
        json={"query": "preferred language", "limit": 5},
    )
    assert search.status_code == 200
    assert len(search.json()["matches"]) == 1
    assert search.json()["matches"][0]["value"] == "English"

    context = client.post(
        "/api/v1/personal/memory/context",
        headers=auth_header(token_a),
        json={"query": "preferred language"},
    )
    assert context.status_code == 200
    assert context.json()["memories"][0]["value"] == "English"
    assert "French" not in context.text


def test_clear_all_memory_is_available_without_active_consent(client: TestClient) -> None:
    token = register_and_login(client, "memory-clear@example.com")
    grant_memory_consent(client, token)
    for key in ("first", "second"):
        response = client.post(
            "/api/v1/personal/memory",
            headers=auth_header(token),
            json={
                "memory_type": "context",
                "key": key,
                "value": key,
                "source": "explicit",
                "confidence": 1.0,
            },
        )
        assert response.status_code == 200
    revoked = client.delete(
        "/api/v1/personal/memory/consent",
        headers=auth_header(token),
    )
    assert revoked.status_code == 200
    cleared = client.delete(
        "/api/v1/personal/memory",
        headers=auth_header(token),
    )
    assert cleared.status_code == 200
    assert cleared.json()["deleted_count"] == 2


def test_memory_detail_and_owner_edit_can_update_key_and_type(
    client: TestClient,
) -> None:
    token = register_and_login(client, "memory-edit-fields@example.com")
    grant_memory_consent(client, token)
    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "context",
            "key": "old-key",
            "value": {"topic": "networking"},
            "source": "explicit",
            "confidence": 0.8,
        },
    )
    assert created.status_code == 200
    memory_id = created.json()["id"]

    fetched = client.get(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token),
    )
    assert fetched.status_code == 200
    assert fetched.json()["key"] == "old-key"

    updated = client.patch(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token),
        json={
            "key": "networking-topic",
            "memory_type": "project",
            "value": {"topic": "networking and security"},
            "confidence": 1.0,
        },
    )
    assert updated.status_code == 200
    assert updated.json()["key"] == "networking-topic"
    assert updated.json()["memory_type"] == "project"

    foreign_token = register_and_login(client, "memory-edit-foreign@example.com")
    foreign_read = client.get(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(foreign_token),
    )
    assert foreign_read.status_code == 404


def test_memory_retrieval_rejects_credential_bearing_queries(
    client: TestClient,
) -> None:
    token = register_and_login(client, "memory-query-validation@example.com")
    grant_memory_consent(client, token)
    response = client.post(
        "/api/v1/personal/memory/search",
        headers=auth_header(token),
        json={"query": "password=do-not-save-this"},
    )
    assert response.status_code == 400
    assert "do-not-save-this" not in response.text



def test_explicit_memory_expiry_cannot_exceed_consent_retention_policy(
    client: TestClient,
) -> None:
    from datetime import datetime, timedelta, timezone

    token = register_and_login(client, "memory-expiry-ceiling@example.com")
    grant_memory_consent(client, token)
    requested_expiry = (
        datetime.now(timezone.utc) + timedelta(days=3000)
    ).isoformat()
    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "context",
            "key": "retention-ceiling",
            "value": "bounded",
            "source": "explicit",
            "confidence": 1.0,
            "expires_at": requested_expiry,
        },
    )
    assert created.status_code == 200
    expires_at = datetime.fromisoformat(created.json()["expires_at"])
    created_at = datetime.fromisoformat(created.json()["created_at"])
    assert expires_at <= created_at + timedelta(days=365)


def test_database_rejects_memory_insert_without_active_consent(
    client: TestClient,
) -> None:
    import sqlite3
    import uuid
    from datetime import datetime, timezone

    token = register_and_login(client, "memory-db-guard@example.com")
    state = get_app_state()
    user = state.identity.resolve_token(token)
    now = datetime.now(timezone.utc).isoformat()
    with pytest.raises(sqlite3.IntegrityError, match="active owner consent"):
        with state.database.transaction():
            state.database.connect().execute(
                """
                INSERT INTO memory_items (
                    id, user_id, memory_type, key, value_json, source,
                    confidence, status, expires_at, created_at, updated_at,
                    consent_id
                )
                VALUES (?, ?, 'context', 'bypass', '"attempt"', 'direct',
                        1.0, 'active', NULL, ?, ?, NULL)
                """,
                (str(uuid.uuid4()), user["id"], now, now),
            )


def test_memory_isolated_by_user(client: TestClient) -> None:
    token_a = register_and_login(client, "memory-a@example.com")
    token_b = register_and_login(client, "memory-b@example.com")
    grant_memory_consent(client, token_a)

    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token_a),
        json={
            "memory_type": "preference",
            "key": "language",
            "value": "English",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    assert created.status_code == 200

    memory_b = client.get(
        "/api/v1/personal/memory",
        headers=auth_header(token_b),
    )
    assert memory_b.status_code == 200
    assert memory_b.json() == []

    export_a = client.post(
        "/api/v1/personal/memory/export",
        headers=auth_header(token_a),
    )
    assert export_a.status_code == 200
    assert export_a.json()["memories"][0]["key"] == "language"


def test_memory_update_delete_and_user_isolation(client: TestClient) -> None:
    token = register_and_login(client, "memory-update@example.com")
    grant_memory_consent(client, token)
    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "goal",
            "key": "project",
            "value": "Build AIBrain",
            "source": "explicit",
            "confidence": 0.9,
        },
    )
    memory_id = created.json()["id"]

    updated = client.patch(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token),
        json={"value": "Build trusted AIBrain", "confidence": 1.0},
    )
    assert updated.status_code == 200
    assert updated.json()["value"] == "Build trusted AIBrain"

    deleted = client.delete(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token),
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_learning_engine_observations_require_explicit_adaptation_approval(
    client: TestClient,
) -> None:
    token = register_and_login(client, "learning@example.com")

    observation = client.post(
        "/api/v1/personal/learning/observations",
        headers=auth_header(token),
        json={
            "source": "explicit-feedback",
            "observation": {"pattern": "prefers concise answers"},
        },
    )
    assert observation.status_code == 200

    adaptation = client.post(
        "/api/v1/personal/learning/adaptations",
        headers=auth_header(token),
        json={"proposal": {"setting": "concise", "confidence": 0.6}},
    )
    assert adaptation.status_code == 200
    assert adaptation.json()["status"] == "pending"

    approved = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation.json()['id']}",
        headers=auth_header(token),
        json={"status": "approved"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    revoked = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation.json()['id']}",
        headers=auth_header(token),
        json={"status": "revoked"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"


def test_safe_tool_discovery_and_execution(client: TestClient) -> None:
    token = register_and_login(client, "tools@example.com")
    listed = client.get(
        "/api/v1/tools",
        headers=auth_header(token),
    )
    assert listed.status_code == 200
    assert listed.json()[0]["tool_id"] == "echo"

    executed = client.post(
        "/api/v1/tools/execute",
        headers=auth_header(token),
        json={"tool_id": "echo", "arguments": {"text": "Hello"}},
    )
    assert executed.status_code == 200
    assert executed.json()["result"]["text"] == "Hello"


def test_unauthenticated_personal_and_tool_routes_are_blocked(
    client: TestClient,
) -> None:
    memory = client.get("/api/v1/personal/memory")
    tools = client.get("/api/v1/tools")
    assert memory.status_code == 401
    assert tools.status_code == 401


def test_local_provider_is_unconfigured_interface() -> None:
    provider = LocalAIProvider()
    assert provider.enabled is False
    assert provider.models == ()

    async def check() -> None:
        with pytest.raises(ProviderUnavailableError):
            await provider.generate(
                ChatRequest(messages=[{"role": "user", "content": "Hello"}])
            )

    asyncio.run(check())


def test_multimodal_contracts_are_typed_without_claiming_runtime_support() -> None:
    media = MediaReference(
        modality=Modality.IMAGE,
        uri="https://example.invalid/image",
        mime_type="image/png",
        size_bytes=100,
    )
    event = StreamEvent(
        event_type="partial",
        sequence=0,
        payload={"text": "hello"},
    )
    assert media.modality == Modality.IMAGE
    assert event.sequence == 0


def test_language_processing_engine_is_an_unimplemented_interface() -> None:
    assert LanguageProcessingEngine.__abstractmethods__


def test_database_migrations_are_versioned_and_persisted(client: TestClient) -> None:
    database = get_app_state().database
    rows = database.connect().execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    assert [row["version"] for row in rows] == list(range(1, 45))


def test_device_key_rotation_migration_installs_challenge_and_audit_guards(
    client: TestClient,
) -> None:
    database = get_app_state().database
    connection = database.connect()
    columns = {
        row["name"] for row in connection.execute(
            "PRAGMA table_info(device_key_rotation_challenges)"
        ).fetchall()
    }
    assert {
        "id", "device_id", "user_id", "nonce_hash", "previous_fingerprint",
        "proposed_public_key_b64", "proposed_fingerprint",
        "expires_at", "used_at", "applied_at", "created_at", "recovery_code_id",
    } <= columns
    event_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='device_security_events'"
    ).fetchone()["sql"]
    assert "device.key_rotated" in event_sql
    trigger_names = {
        row["name"] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
    }
    assert "prevent_device_key_rotation_without_proof" in trigger_names
    recovery_guard = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='trigger' "
        "AND name='prevent_device_key_rotation_without_proof'"
    ).fetchone()["sql"]
    assert "recovery_code_id" in recovery_guard
    assert "webauthn_recovery_codes" in recovery_guard
    assert "r.used_at IS NOT NULL" in recovery_guard
    assert "prevent_device_security_event_update" in trigger_names
    assert "prevent_device_security_event_delete" in trigger_names
    assert "audit_device_enrollment" in trigger_names
    assert "audit_device_key_registration" in trigger_names
    assert "audit_device_activation" in trigger_names
    assert "audit_device_revocation" in trigger_names
    assert "audit_device_session" in trigger_names


def test_streaming_intelligence_endpoint_is_available(client: TestClient) -> None:
    response = client.post(
        "/api/v1/intelligence/process/stream",
        json={"messages": [{"role": "user", "content": "Hello"}]},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "data:" in response.text


def test_account_deletion_removes_personal_records(client: TestClient) -> None:
    token = register_and_login(client, "delete-all@example.com")
    grant_memory_consent(client, token)

    memory = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "preference",
            "key": "delete-me",
            "value": "private",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    assert memory.status_code == 200
    observation = client.post(
        "/api/v1/personal/learning/observations",
        headers=auth_header(token),
        json={"source": "explicit", "observation": {"pattern": "private"}},
    )
    assert observation.status_code == 200
    adaptation = client.post(
        "/api/v1/personal/learning/adaptations",
        headers=auth_header(token),
        json={"proposal": {"setting": "private"}},
    )
    assert adaptation.status_code == 200

    # Seed linked WebAuthn records to exercise account-deletion cleanup.
    state = get_app_state()
    user = state.identity.resolve_token(token)
    user_id = user["id"]
    connection = state.database.connect()
    timestamp = "2026-11-22T00:00:00+00:00"

    with state.database.transaction():
        connection.execute(
            """INSERT INTO tool_requests (
                id, user_id, tool_id, arguments_json, status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("delete-webauthn-request", user_id, "test-tool", "{}", "pending",
             timestamp, timestamp),
        )
        connection.execute(
            """INSERT INTO webauthn_credentials (
                id, user_id, credential_id, public_key, created_at
            ) VALUES (?, ?, ?, ?, ?)""",
            ("delete-webauthn-credential", user_id,
             "external-delete-credential", b"test-public-key", timestamp),
        )
        connection.execute(
            """INSERT INTO webauthn_challenges (
                id, user_id, challenge_hash, purpose, request_id,
                proposal_digest, contract_fingerprint, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("delete-webauthn-challenge", user_id, "delete-challenge-hash",
             "tool_approval", "delete-webauthn-request", "test-digest",
             "test-fingerprint", "2027-01-01T00:00:00+00:00", timestamp),
        )
        connection.execute(
            """INSERT INTO webauthn_recovery_codes (
                id, user_id, code_hash, created_at
            ) VALUES (?, ?, ?, ?)""",
            ("delete-webauthn-recovery", user_id,
             "delete-recovery-hash", timestamp),
        )
        connection.execute(
            """INSERT INTO tool_authorizations (
                id, user_id, request_id, challenge_id, credential_id,
                proposal_digest, contract_fingerprint, authorized_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("delete-webauthn-authorization", user_id,
             "delete-webauthn-request", "delete-webauthn-challenge",
             "delete-webauthn-credential", "test-digest",
             "test-fingerprint", timestamp),
        )

    deleted = client.delete(
        "/api/v1/auth/me",
        headers=auth_header(token),
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    after = client.get(
        "/api/v1/auth/me",
        headers=auth_header(token),
    )
    assert after.status_code == 401

    state = get_app_state()
    user_row = state.database.connect().execute(
        "SELECT id FROM users "
        "WHERE email = ?",
        ("delete-all@example.com",),
    ).fetchone()
    assert user_row is not None
    user_id = user_row["id"]
    for table in (
        "memory_items",
        "memory_consents",
        "observations",
        "learning_evaluations",
        "learning_adaptation_events",
        "adaptations",
        "tool_authorizations",
        "webauthn_challenges",
        "webauthn_recovery_codes",
        "webauthn_credentials",
        "tool_requests",
    ):
        row = state.database.connect().execute(
            f"SELECT 1 FROM {table} WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        assert row is None


def test_deleted_user_cannot_create_sessions_or_personal_records(
    client: TestClient,
) -> None:
    import sqlite3

    token = register_and_login(client, "deleted-write@example.com")
    state = get_app_state()
    user = state.identity.resolve_token(token)
    user_id = user["id"]

    state.identity.delete_user(user_id)
    # Simulate requests that passed authentication before account deletion.
    with pytest.raises(sqlite3.IntegrityError):
        state.memory.create(
            user_id,
            memory_type="preference",
            key="late-memory",
            value="must not persist",
            source="explicit",
            confidence=1.0,
        )

    with pytest.raises(sqlite3.IntegrityError):
        state.learning.record_observation(
            user_id,
            source="explicit",
            observation={"pattern": "must not persist"},
        )

    with pytest.raises(sqlite3.IntegrityError):
        state.learning.propose_adaptation(
            user_id,
            proposal={"setting": "must not persist"},
        )

    with pytest.raises(sqlite3.IntegrityError):
        state.tool_requests.create(
            user_id,
            tool_id="echo",
            arguments={"text": "must not persist"},
            status="approved",
        )

    with pytest.raises(sqlite3.IntegrityError):
        state.database.connect().execute(
            "INSERT INTO sessions "
            "(token_hash, user_id, expires_at, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                "stale-session-hash",
                user_id,
                "2999-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    # Sessions are retained for auditability, but must all be revoked.
    connection = state.database.connect()
    session_count = connection.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?",
        (user_id,),
    ).fetchone()[0]
    active_session_count = connection.execute(
        "SELECT COUNT(*) FROM sessions "
        "WHERE user_id = ? AND revoked_at IS NULL",
        (user_id,),
    ).fetchone()[0]

    assert session_count >= 1
    assert active_session_count == 0

    # Personal records must be physically removed.
    for table in (
        "memory_items",
        "memory_consents",
        "observations",
        "learning_evaluations",
        "learning_adaptation_events",
        "adaptations",
        "tool_requests",
    ):
        row = connection.execute(
            f"SELECT 1 FROM {table} WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        assert row is None, f"Unexpected personal data remained in {table}"


def test_cross_user_memory_read_update_delete_is_rejected(
    client: TestClient,
) -> None:
    token_a = register_and_login(client, "owner@example.com")
    token_b = register_and_login(client, "other@example.com")
    grant_memory_consent(client, token_a)
    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token_a),
        json={
            "memory_type": "preference",
            "key": "private",
            "value": "owner-only",
            "source": "explicit",
            "confidence": 1.0,
        },
    )
    memory_id = created.json()["id"]

    read = client.patch(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token_b),
        json={"value": "hijacked", "confidence": 1.0},
    )
    delete = client.delete(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token_b),
    )
    assert read.status_code in {404, 400}
    assert delete.status_code == 404


def test_expired_memory_is_not_listed_retrieved_updated_or_exported(
    client: TestClient,
) -> None:
    token = register_and_login(client, "expired@example.com")
    grant_memory_consent(client, token)
    created = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "context",
            "key": "old",
            "value": "expired-value",
            "source": "test",
            "confidence": 1.0,
            "expires_at": "2000-01-01T00:00:00+00:00",
        },
    )
    assert created.status_code == 200
    memory_id = created.json()["id"]

    listed = client.get(
        "/api/v1/personal/memory",
        headers=auth_header(token),
    )
    assert listed.status_code == 200
    assert memory_id not in {item["id"] for item in listed.json()}

    updated = client.patch(
        f"/api/v1/personal/memory/{memory_id}",
        headers=auth_header(token),
        json={"value": "revived", "confidence": 1.0},
    )
    assert updated.status_code == 404

    exported = client.post(
        "/api/v1/personal/memory/export",
        headers=auth_header(token),
    )
    assert memory_id not in {
        item["id"] for item in exported.json()["memories"]
    }


def test_cross_user_learning_access_is_sanitized(
    client: TestClient,
) -> None:
    token_a = register_and_login(client, "learning-owner@example.com")
    token_b = register_and_login(client, "learning-other@example.com")
    observation = client.post(
        "/api/v1/personal/learning/observations",
        headers=auth_header(token_a),
        json={"source": "explicit", "observation": {"pattern": "private"}},
    )
    observation_id = observation.json()["id"]
    adaptation = client.post(
        "/api/v1/personal/learning/adaptations",
        headers=auth_header(token_a),
        json={"proposal": {"setting": "private"}},
    )
    adaptation_id = adaptation.json()["id"]

    observation_read = client.get(
        f"/api/v1/personal/learning/observations/{observation_id}",
        headers=auth_header(token_b),
    )
    adaptation_read = client.get(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=auth_header(token_b),
    )
    adaptation_update = client.patch(
        f"/api/v1/personal/learning/adaptations/{adaptation_id}",
        headers=auth_header(token_b),
        json={"status": "approved"},
    )
    assert observation_read.status_code == 404
    assert adaptation_read.status_code == 404
    assert adaptation_update.status_code == 404


@pytest.mark.parametrize(
    "value",
    [
        {"api_key": "secret"},
        {"one": {"two": {"three": {"four": {"five": {"six": {"seven": "too deep"}}}}}}},
        {"items": list(range(101))},
        {"value": "Bearer abcdefghijklmnop"},
    ],
)
def test_personal_payload_validation_rejects_sensitive_or_unbounded_values(
    client: TestClient,
    value: dict,
) -> None:
    token = register_and_login(client, f"payload-{id(value)}@example.com")
    response = client.post(
        "/api/v1/personal/memory",
        headers=auth_header(token),
        json={
            "memory_type": "context",
            "key": "payload",
            "value": value,
            "source": "test",
            "confidence": 1.0,
        },
    )
    assert response.status_code in {400, 422}
    assert "routing_summary" not in response.text


def test_file_database_persists_across_database_instances(
    tmp_path,
) -> None:
    from backend.app.persistence.database import Database

    path = tmp_path / "aibrain.db"
    first = Database(f"sqlite:///{path}")
    first.connect().execute(
        "INSERT INTO users "
        "(id, email, password_salt, password_hash, display_name, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "persisted-user",
            "persisted@example.com",
            "salt",
            "hash",
            "Persisted",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    first.connect().commit()
    first.close()

    second = Database(f"sqlite:///{path}")
    row = second.connect().execute(
        "SELECT email FROM users WHERE id = ?",
        ("persisted-user",),
    ).fetchone()
    assert row["email"] == "persisted@example.com"
    second.close()


def test_database_transaction_rolls_back_on_error(tmp_path) -> None:
    from backend.app.persistence.database import Database

    database = Database(f"sqlite:///{tmp_path / 'rollback.db'}")
    try:
        with database.transaction():
            database.connect().execute(
                "INSERT INTO users "
                "(id, email, password_salt, password_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "rollback-user",
                    "rollback@example.com",
                    "salt",
                    "hash",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            raise RuntimeError("forced rollback")
    except RuntimeError:
        pass

    row = database.connect().execute(
        "SELECT 1 FROM users WHERE id = ?",
        ("rollback-user",),
    ).fetchone()
    assert row is None
    database.close()


def test_tool_request_owner_and_replay_lifecycle(
    client: TestClient,
) -> None:
    token_a = register_and_login(client, "tool-owner@example.com")
    token_b = register_and_login(client, "tool-other@example.com")

    executed = client.post(
        "/api/v1/tools/execute",
        headers=auth_header(token_a),
        json={"tool_id": "echo", "arguments": {"text": "owned"}},
    )
    assert executed.status_code == 200

    state = get_app_state()
    row = state.database.connect().execute(
        "SELECT id, user_id FROM tool_requests "
        "WHERE status = 'completed' "
        "ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    assert row is not None

    cancelled = client.post(
        f"/api/v1/tools/requests/{row['id']}/cancel",
        headers=auth_header(token_b),
    )
    confirm = client.post(
        f"/api/v1/tools/requests/{row['id']}/confirm",
        headers=auth_header(token_b),
    )
    assert cancelled.status_code == 404
    assert confirm.status_code == 404


def test_tool_execution_request_cannot_be_replayed() -> None:
    from backend.app.app_state import get_app_state
    from backend.app.tools import (
        ToolExecutionGateway,
        ToolRegistry,
        ToolContract,
        ToolRisk,
    )

    state = get_app_state()
    user_id = "tool-replay-test-user"
    now = "2026-01-01T00:00:00+00:00"
    state.database.connect().execute(
        "INSERT OR IGNORE INTO users "
        "(id, email, password_salt, password_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, "tool-replay-test@example.com", "salt", "hash", now),
    )
    state.database.connect().commit()

    registry = ToolRegistry()
    registry.register(ToolContract(
        tool_id="echo",
        name="Echo",
        description="Echo",
        risk=ToolRisk.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "maxLength": 4096},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema={"text": {"type": "string"}},
    ))
    gateway = ToolExecutionGateway(registry, state.database)

    proposal = gateway.propose(
        user_id,
        tool_id="echo",
        arguments={"text": "single execution"},
    )
    result = gateway.execute(proposal, user_id=user_id)

    assert result["result"]["text"] == "single execution"

    with pytest.raises(PermissionError):
        gateway.execute(proposal, user_id=user_id)

    persisted = gateway._tool_requests.get(user_id, proposal["id"])
    assert persisted["status"] == "completed"
    assert persisted["consumed_at"] is not None


def test_tool_request_can_only_be_claimed_once_concurrently(
    tmp_path,
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from backend.app.persistence.database import Database
    from backend.app.persistence.tool_requests import ToolRequestRepository

    database_url = f"sqlite:///{tmp_path / 'concurrent-tool-claims.db'}"
    database_a = Database(database_url)
    database_b = Database(database_url)

    try:
        user_id = "tool-concurrent-claim-user"
        now = "2026-01-01T00:00:00+00:00"

        database_a.connect().execute(
            "INSERT INTO users "
            "(id, email, password_salt, password_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, "tool-concurrent-claim@example.com", "salt", "hash", now),
        )
        database_a.connect().commit()

        repository_a = ToolRequestRepository(database_a)
        repository_b = ToolRequestRepository(database_b)

        request = repository_a.create(
            user_id,
            tool_id="echo",
            arguments={"text": "claim once"},
            status="approved",
            authorization_policy="read_only",
        )

        barrier = Barrier(2)

        def attempt_claim(repository) -> str:
            barrier.wait(timeout=5)
            try:
                claimed = repository.claim_for_execution(
                    user_id,
                    request["id"],
                )
                return claimed["status"]
            except PermissionError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(attempt_claim, repository_a),
                executor.submit(attempt_claim, repository_b),
            ]
            results = [future.result(timeout=10) for future in futures]

        assert sorted(results) == ["executing", "rejected"]

        persisted = repository_a.get(user_id, request["id"])
        assert persisted["status"] == "executing"
        assert persisted["consumed_at"] is not None
    finally:
        database_a.close()
        database_b.close()



def test_expired_tool_confirmation_is_rejected() -> None:
    from backend.app.app_state import get_app_state
    from backend.app.tools import ToolExecutionGateway, ToolRegistry, ToolContract, ToolRisk

    state = get_app_state()
    now = "2026-01-01T00:00:00+00:00"
    state.database.connect().execute(
        "INSERT OR IGNORE INTO users "
        "(id, email, password_salt, password_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("test-user", "tool-confirm@example.com", "salt", "hash", now),
    )
    state.database.connect().commit()
    registry = ToolRegistry()
    registry.register(ToolContract(
        tool_id="echo",
        name="Echo",
        description="Echo",
        risk=ToolRisk.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "maxLength": 4096},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema={"text": {"type": "string"}},
    ))
    gateway = ToolExecutionGateway(
        registry,
        state.database,
        confirmation_ttl_seconds=-1,
    )

    proposal = gateway.propose(
        "test-user",
        tool_id="echo",
        arguments={"text": "hello"},
    )
    with pytest.raises(PermissionError, match="expired"):
        gateway.execute(proposal, user_id="test-user")


def test_revoked_and_invalid_session_tokens_are_rejected(
    client: TestClient,
) -> None:
    token = register_and_login(client, "session@example.com")
    logout = client.post(
        "/api/v1/auth/logout",
        headers=auth_header(token),
    )
    assert logout.status_code == 200
    replay = client.get(
        "/api/v1/auth/me",
        headers=auth_header(token),
    )
    assert replay.status_code == 401

    invalid = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert invalid.status_code == 401


def test_logout_rejects_missing_or_empty_bearer_token(
    client: TestClient,
) -> None:
    missing = client.post("/api/v1/auth/logout")
    assert missing.status_code == 401

    empty = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": "Bearer    "},
    )
    assert empty.status_code == 401


def test_logout_is_idempotent_for_unknown_nonempty_token(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": "Bearer unknown-token"},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "logged_out"}


def test_expired_session_is_rejected(
    client: TestClient,
) -> None:
    account_token = register_and_login(client, "expired-session@example.com")
    state = get_app_state()
    user_id = state.identity.resolve_token(account_token)["id"]
    token = "expired-session-test-token"
    token_hash = __import__("hashlib").sha256(
        token.encode("utf-8")
    ).hexdigest()
    state.database.connect().execute(
        """
        INSERT INTO sessions (
            token_hash, user_id, expires_at, created_at, device_id, auth_method
        ) VALUES (?, ?, ?, ?, NULL, 'account')
        """,
        (
            token_hash,
            user_id,
            "2000-01-01T00:00:00+00:00",
            "1999-12-31T00:00:00+00:00",
        ),
    )
    state.database.connect().commit()

    response = client.get(
        "/api/v1/auth/me",
        headers=auth_header(token),
    )
    assert response.status_code == 401

    remaining = state.database.connect().execute(
        "SELECT COUNT(*) FROM sessions WHERE token_hash = ?",
        (token_hash,),
    ).fetchone()[0]
    assert remaining == 1

    assert state.identity.cleanup_sessions() >= 1

    after_cleanup = state.database.connect().execute(
        "SELECT COUNT(*) FROM sessions WHERE token_hash = ?",
        (token_hash,),
    ).fetchone()[0]
    assert after_cleanup == 0


def test_login_rate_limiter_blocks_repeated_failures() -> None:
    from backend.app.auth.rate_limit import LoginRateLimiter

    limiter = LoginRateLimiter(limit=2, window_seconds=60)
    assert limiter.is_limited("user@example.com") is False
    limiter.record_attempt("user@example.com")
    limiter.record_attempt("user@example.com")
    assert limiter.is_limited("user@example.com") is True


def test_login_rate_limiter_bounds_tracked_identities() -> None:
    from backend.app.auth.rate_limit import LoginRateLimiter

    limiter = LoginRateLimiter(limit=2, window_seconds=60, max_entries=2)

    limiter.record_attempt("first@example.com")
    limiter.record_attempt("second@example.com")
    limiter.record_attempt("third@example.com")

    assert len(limiter._attempts) == 2
    assert "first@example.com" not in limiter._attempts
    assert "third@example.com" in limiter._attempts


def test_login_rate_limiter_cleans_expired_entries(monkeypatch) -> None:
    import backend.app.auth.rate_limit as rate_limit_module
    from backend.app.auth.rate_limit import LoginRateLimiter

    now = [100.0]
    monkeypatch.setattr(
        rate_limit_module.time,
        "monotonic",
        lambda: now[0],
    )

    limiter = LoginRateLimiter(
        limit=2,
        window_seconds=10,
        max_entries=10,
    )

    limiter.record_attempt("expired@example.com")
    now[0] = 111.0
    limiter._last_cleanup = 100.0

    assert limiter.is_limited("expired@example.com") is False
    assert "expired@example.com" not in limiter._attempts


def test_login_rate_limiter_reset_clears_attempts() -> None:
    from backend.app.auth.rate_limit import LoginRateLimiter

    limiter = LoginRateLimiter(limit=2, window_seconds=60)
    limiter.record_attempt("user@example.com")
    limiter.reset("user@example.com")

    assert limiter.is_limited("user@example.com") is False
    assert "user@example.com" not in limiter._attempts


def test_concurrent_file_database_writes_and_reads(tmp_path) -> None:
    import threading
    from backend.app.persistence.database import Database

    database = Database(f"sqlite:///{tmp_path / 'concurrent.db'}")
    barrier = threading.Barrier(3)
    errors = []

    def writer(index: int) -> None:
        try:
            barrier.wait()
            with database.transaction():
                database.connect().execute(
                    "INSERT INTO users "
                    "(id, email, password_salt, password_hash, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        f"user-{index}",
                        f"user-{index}@example.com",
                        "salt",
                        "hash",
                        "2026-01-01T00:00:00+00:00",
                    ),
                )
        except Exception as error:
            errors.append(error)

    threads = [
        threading.Thread(target=writer, args=(index,))
        for index in range(2)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert errors == []
    rows = database.connect().execute(
        "SELECT COUNT(*) AS count FROM users"
    ).fetchone()
    assert rows["count"] == 2
    database.close()


def test_migrations_are_idempotent_on_file_database(tmp_path) -> None:
    from backend.app.persistence.database import Database

    expected_versions = list(range(1, 45))
    path = tmp_path / "migrations.db"
    first = Database(f"sqlite:///{path}")
    first.migrate()
    rows = first.connect().execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    assert [row["version"] for row in rows] == expected_versions
    first.close()

    second = Database(f"sqlite:///{path}")
    second.migrate()
    rows = second.connect().execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    assert [row["version"] for row in rows] == expected_versions
    second.close()


def test_migration_nine_creates_constrained_execution_attempt_table(
    client: TestClient,
) -> None:
    import sqlite3

    state = get_app_state()
    # Serialize direct SQL assertions with the lifespan recovery worker.
    with state.database.transaction(immediate=True):
        connection = state.database.connect()
        user_id = "migration-nine-user"
        timestamp = "2026-11-23T00:00:00+00:00"

        connection.execute(
            "INSERT OR IGNORE INTO users "
            "(id, email, password_salt, password_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, "migration-nine@example.com", "salt", "hash", timestamp),
        )
        connection.execute(
            """
            INSERT INTO tool_requests (
                id, user_id, tool_id, arguments_json, status,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "migration-nine-request",
                user_id,
                "echo",
                "{}",
                "executing",
                timestamp,
                timestamp,
            ),
        )

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(tool_execution_attempts)"
            ).fetchall()
        }
        assert {
            "id",
            "user_id",
            "request_id",
            "idempotency_key",
            "status",
            "claimed_at",
            "updated_at",
            "finished_at",
            "error_code",
        } <= columns

        connection.execute(
            """
            INSERT INTO tool_execution_attempts (
                id, user_id, request_id, idempotency_key,
                status, claimed_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "migration-nine-attempt",
                user_id,
                "migration-nine-request",
                "migration-nine-idempotency-key",
                "claimed",
                timestamp,
                timestamp,
            ),
        )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key,
                    status, claimed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "migration-nine-duplicate",
                    user_id,
                    "migration-nine-request",
                    "another-idempotency-key",
                    "claimed",
                    timestamp,
                    timestamp,
                ),
            )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key,
                    status, claimed_at, updated_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "migration-nine-invalid-status",
                    user_id,
                    "migration-nine-request",
                    "invalid-status-key",
                    "retrying",
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO tool_execution_attempts (
                    id, user_id, request_id, idempotency_key,
                    status, claimed_at, updated_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "migration-nine-invalid-finished-state",
                    user_id,
                    "migration-nine-request",
                    "invalid-finished-state-key",
                    "succeeded",
                    timestamp,
                    timestamp,
                    None,
                ),
            )

        attempt = connection.execute(
            "SELECT status, finished_at FROM tool_execution_attempts WHERE id = ?",
            ("migration-nine-attempt",),
        ).fetchone()
        assert attempt["status"] == "claimed"
        assert attempt["finished_at"] is None


def test_migration_failure_prevents_database_initialization(
    tmp_path,
    monkeypatch,
) -> None:
    from backend.app.persistence.database import Database

    def fail_migration(self, connection, version, script):
        raise RuntimeError("migration sentinel")

    monkeypatch.setattr(Database, "_apply_migration", fail_migration)
    with pytest.raises(RuntimeError, match="migration sentinel"):
        Database(f"sqlite:///{tmp_path / 'migration-failure.db'}")


def test_migration_rolls_back_partial_schema_changes(tmp_path) -> None:
    import sqlite3

    from backend.app.persistence.database import Database

    database = Database(f"sqlite:///{tmp_path / 'migration-rollback.db'}")
    connection = database.connect()

    with pytest.raises(sqlite3.OperationalError):
        database._apply_migration(
            connection,
            999,
            """
            CREATE TABLE migration_partial_test (id INTEGER PRIMARY KEY);
            CREATE TABLE migration_partial_test (id INTEGER PRIMARY KEY);
            """,
        )

    table = connection.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'migration_partial_test'"
    ).fetchone()
    version = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = 999"
    ).fetchone()

    assert table is None
    assert version is None
    database.close()


def test_transaction_releases_lock_when_begin_fails(
    tmp_path,
    monkeypatch,
) -> None:
    from backend.app.persistence.database import Database

    database = Database(f"sqlite:///{tmp_path / 'transaction-lock.db'}")
    original_connect = database.connect
    original_connection = original_connect()

    class BeginFailureConnection:
        def execute(self, statement):
            if statement == "BEGIN":
                raise RuntimeError("begin sentinel")
            return original_connection.execute(statement)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                database,
                "connect",
                lambda: BeginFailureConnection(),
            )

            with pytest.raises(RuntimeError, match="begin sentinel"):
                with database.transaction():
                    pass

        # The failed BEGIN must not leave the database lock held.
        assert database._lock.acquire(timeout=0.2)
        database._lock.release()
    finally:
        database.close()


def test_migration_twenty_backfills_legacy_reconciliation_json(tmp_path) -> None:
    import json

    from backend.app.persistence.database import Database

    path = tmp_path / "legacy-reconciliation.db"
    database = Database(f"sqlite:///{path}")
    connection = database.connect()
    timestamp = "2026-11-24T12:00:00+00:00"
    user_id = "legacy-reconciliation-user"
    request_id = "legacy-reconciliation-request"
    connection.execute(
        """
        INSERT INTO users (
            id, email, password_salt, password_hash, created_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, "legacy-reconciliation@example.com", "salt", "hash", timestamp),
    )
    legacy_reconciliation = {
        "outcome": "failed",
        "reconciled_by": user_id,
        "reconciled_at": timestamp,
        "note": "Legacy resolution carried forward",
    }
    connection.execute(
        """
        INSERT INTO tool_requests (
            id, user_id, tool_id, arguments_json, status,
            created_at, updated_at, audit_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            user_id,
            "legacy-tool",
            "{}",
            "failed",
            timestamp,
            timestamp,
            json.dumps({"execution_reconciliation": legacy_reconciliation}),
        ),
    )
    connection.execute(
        """
        INSERT INTO tool_requests (
            id, user_id, tool_id, arguments_json, status,
            created_at, updated_at, audit_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "malformed-legacy-reconciliation-request",
            user_id,
            "legacy-tool",
            "{}",
            "failed",
            timestamp,
            timestamp,
            "{not-valid-json",
        ),
    )
    connection.commit()

    # Simulate upgrading a database that predates migration 20.
    connection.execute("DROP TABLE tool_execution_reconciliation_events")
    connection.execute("DELETE FROM schema_migrations WHERE version = 20")
    connection.commit()
    database.migrate()

    migrated = database.connect().execute(
        """
        SELECT user_id, request_id, outcome, note, error_code, created_at
        FROM tool_execution_reconciliation_events
        WHERE user_id = ? AND request_id = ?
        """,
        (user_id, request_id),
    ).fetchone()
    assert migrated is not None
    assert migrated["outcome"] == "failed"
    assert migrated["note"] == "Legacy resolution carried forward"
    assert migrated["error_code"] is None
    assert migrated["created_at"] == timestamp

    remaining_audit = database.connect().execute(
        "SELECT audit_json FROM tool_requests WHERE id = ?",
        (request_id,),
    ).fetchone()["audit_json"]
    assert json.loads(remaining_audit) == {}

    malformed_audit = database.connect().execute(
        "SELECT audit_json FROM tool_requests "
        "WHERE id = 'malformed-legacy-reconciliation-request'"
    ).fetchone()["audit_json"]
    assert malformed_audit == "{not-valid-json"
    assert database.connect().execute(
        "SELECT COUNT(*) FROM tool_execution_reconciliation_events "
        "WHERE request_id = 'malformed-legacy-reconciliation-request'"
    ).fetchone()[0] == 0
    database.close()
