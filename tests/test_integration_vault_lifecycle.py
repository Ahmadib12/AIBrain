import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.identity import IdentityRepository
from backend.app.persistence.integration_connections import IntegrationConnectionRepository
from backend.app.tools.integration_lifecycle import (
    IntegrationConnectionLifecycle,
    ProviderVerification,
    ProviderVerifierRegistry,
)
from backend.app.tools.integration_network import (
    ProviderEgressPolicy,
    ProviderEgressRejected,
)
from backend.app.tools.integration_vault import (
    IntegrationSecretVault,
    IntegrationVaultUnavailable,
)


class FakeVerifier:
    verifier_id = "test-provider-verifier"

    async def verify(
        self, *, user_id, integration_id, connection_id,
        credential_material, requested_scopes,
    ):
        assert credential_material["access_token"] == "never-log-this"
        return ProviderVerification(
            granted_scopes=tuple(requested_scopes),
            provider_subject_fingerprint="a" * 64,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )


@pytest.fixture
def integration_state():
    database = Database("sqlite:///:memory:")
    identity = IdentityRepository(database, session_ttl_seconds=3600)
    owner = identity.register(
        email="vault-owner@example.com",
        password="safe-password-123",
        display_name="Owner",
    )
    connections = IntegrationConnectionRepository(database)
    connection = connections.create_pending(
        owner["id"], "calendar", ["calendar.events.read"],
        consent_version="calendar-v1",
    )
    key = base64.b64encode(os.urandom(32)).decode("ascii")
    vault = IntegrationSecretVault(database, key)
    verifiers = ProviderVerifierRegistry()
    verifiers.register("calendar", FakeVerifier())
    lifecycle = IntegrationConnectionLifecycle(
        connections=connections, vault=vault, verifiers=verifiers
    )
    try:
        yield database, owner["id"], connection, connections, vault, lifecycle
    finally:
        database.shutdown()


def _activate(integration_state):
    _, owner_id, connection, _, _, lifecycle = integration_state
    return asyncio.run(lifecycle.verify_and_activate(
        owner_id, connection["id"], {"access_token": "never-log-this"}
    ))


def test_vault_encrypts_credentials_and_trusted_verifier_activates(integration_state):
    database, owner_id, connection, connections, vault, lifecycle = integration_state
    active = _activate(integration_state)
    assert active["status"] == "active"
    assert active["grants"][0]["status"] == "active"
    row = database.connect().execute(
        "SELECT ciphertext,nonce,secret_ref FROM integration_secrets WHERE connection_id=?",
        (connection["id"],),
    ).fetchone()
    assert row is not None
    assert b"never-log-this" not in row["ciphertext"]
    assert vault.load(owner_id, connection["id"], "calendar") == {
        "access_token": "never-log-this"
    }
    assert "secret_ref" not in connections.get(owner_id, connection["id"])


def test_missing_vault_key_fails_closed():
    database = Database("sqlite:///:memory:")
    vault = IntegrationSecretVault(database, None)
    assert vault.available is False
    with pytest.raises(IntegrationVaultUnavailable):
        vault.store("owner", "connection", "calendar", {"token": "x"})
    database.shutdown()


def test_database_rejects_activation_without_real_vault_record(integration_state):
    database, _, connection, _, _, _ = integration_state
    with pytest.raises(Exception):
        database.connect().execute(
            """UPDATE integration_connections
               SET status='active',verified_at=?,secret_ref='vault:forged'
               WHERE id=?""",
            (datetime.now(timezone.utc).isoformat(), connection["id"]),
        )


def test_revocation_destroys_encrypted_credentials(integration_state):
    database, owner_id, connection, connections, vault, _ = integration_state
    _activate(integration_state)
    assert database.connect().execute(
        "SELECT COUNT(*) FROM integration_secrets WHERE connection_id=?",
        (connection["id"],),
    ).fetchone()[0] == 1
    revoked = connections.revoke(owner_id, connection["id"])
    assert revoked["status"] == "revoked"
    assert database.connect().execute(
        "SELECT COUNT(*) FROM integration_secrets WHERE connection_id=?",
        (connection["id"],),
    ).fetchone()[0] == 0
    with pytest.raises(LookupError):
        vault.load(owner_id, connection["id"], "calendar")


def test_expiry_destroys_vault_credentials_and_grants(integration_state):
    database, owner_id, connection, connections, vault, _ = integration_state
    _activate(integration_state)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    database.connect().execute(
        "UPDATE integration_connections SET expires_at=? WHERE id=?",
        (past, connection["id"]),
    )
    assert connections.expire_due() >= 1
    expired = connections.get(owner_id, connection["id"])
    assert expired["status"] == "expired"
    assert expired["grants"][0]["status"] == "expired"
    assert database.connect().execute(
        "SELECT COUNT(*) FROM integration_secrets WHERE connection_id=?",
        (connection["id"],),
    ).fetchone()[0] == 0


def test_vault_authentication_detects_ciphertext_tampering(integration_state):
    database, owner_id, connection, _, vault, _ = integration_state
    _activate(integration_state)
    database.connect().execute(
        "UPDATE integration_secrets SET ciphertext=? WHERE connection_id=?",
        (b"x" * 64, connection["id"]),
    )
    with pytest.raises(IntegrationVaultUnavailable):
        vault.load(owner_id, connection["id"], "calendar")


def test_provider_egress_requires_allowlisted_https_and_public_dns():
    policy = ProviderEgressPolicy({"api.example.com"})
    assert policy.validate_url("https://api.example.com/v1/me") == "api.example.com"
    with pytest.raises(ProviderEgressRejected):
        policy.validate_url("http://api.example.com/v1/me")
    with pytest.raises(ProviderEgressRejected):
        policy.validate_url("https://127.0.0.1/admin")
    with pytest.raises(ProviderEgressRejected):
        policy.validate_url("https://attacker.example/admin")
    with pytest.raises(ProviderEgressRejected):
        policy.validate_resolved_addresses(("127.0.0.1",))
    assert policy.validate_resolved_addresses(("8.8.8.8",)) == ("8.8.8.8",)


def test_vault_key_must_be_exactly_32_bytes():
    from backend.app.config import Settings

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        Settings(integration_vault_key_b64=base64.b64encode(b"too-short").decode())
