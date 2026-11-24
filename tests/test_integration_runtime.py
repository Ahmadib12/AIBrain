import asyncio
from datetime import datetime, timezone

import pytest

from backend.app.persistence.database import Database
from backend.app.persistence.identity import IdentityRepository
from backend.app.persistence.integration_connections import IntegrationConnectionRepository
from backend.app.tools.contracts import ToolContract, ToolRisk
from backend.app.tools.integration_runtime import (
    IntegrationAdapterRegistry,
    ReadOnlyIntegrationRuntime,
)
from backend.app.tools.integrations import (
    IntegrationManifest,
    IntegrationRegistry,
    IntegrationTool,
)


class FakeReadAdapter:
    def __init__(self, result=None):
        self.result = result or {"items": ["one"]}
        self.calls = 0

    async def execute(self, *, user_id, connection_id, tool_id, arguments):
        self.calls += 1
        return self.result


def _contract():
    return ToolContract(
        tool_id="catalog.search",
        name="Catalog search",
        description="Search a connected catalog",
        risk=ToolRisk.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 100}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 10,
                }
            },
            "required": ["items"],
            "additionalProperties": False,
        },
    )


@pytest.fixture
def runtime_state():
    database = Database("sqlite:///:memory:")
    identity = IdentityRepository(database, session_ttl_seconds=3600)
    owner = identity.register(
        email="runtime-owner@example.com",
        password="safe-password-123",
        display_name="Owner",
    )
    connections = IntegrationConnectionRepository(database)
    connection = connections.create_pending(
        owner["id"], "catalog", ["catalog.search"], consent_version="v1"
    )
    manifests = IntegrationRegistry()
    manifests.register(IntegrationManifest(
        integration_id="catalog",
        name="Catalog",
        description="Test catalog",
        version="1",
        tools=(IntegrationTool(_contract(), ("catalog.search",)),),
    ))
    adapters = IntegrationAdapterRegistry()
    try:
        yield database, owner["id"], connection, connections, manifests, adapters
    finally:
        database.shutdown()


def _activate_test_connection(database, connection):
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction(immediate=True):
        database.connect().execute(
            """INSERT INTO integration_secrets
               (secret_ref,user_id,connection_id,integration_id,nonce,ciphertext,
                key_version,created_at,updated_at)
               VALUES ('vault-ref:test',?,?,?, ?, ?,1,?,?)""",
            (
                connection["user_id"] if "user_id" in connection else database.connect().execute(
                    "SELECT user_id FROM integration_connections WHERE id=?",
                    (connection["id"],),
                ).fetchone()["user_id"],
                connection["id"], "catalog", b"n" * 12, b"c" * 16, now, now,
            ),
        )
        database.connect().execute(
            """UPDATE integration_connections
               SET status='active',verified_at=?,secret_ref='vault-ref:test',
                   updated_at=? WHERE id=?""",
            (now, now, connection["id"]),
        )
        database.connect().execute(
            """UPDATE integration_connection_grants SET status='active'
               WHERE connection_id=?""",
            (connection["id"],),
        )


def test_pending_consent_cannot_execute_even_with_trusted_adapter(runtime_state):
    _, owner_id, connection, connections, manifests, adapters = runtime_state
    adapter = FakeReadAdapter()
    adapters.register("catalog", adapter)
    runtime = ReadOnlyIntegrationRuntime(
        manifests=manifests, adapters=adapters, connections=connections
    )
    with pytest.raises(PermissionError, match="active owner connection"):
        asyncio.run(runtime.execute(
            owner_id, connection["id"], "catalog.search", {"query": "hello"}
        ))
    assert adapter.calls == 0


def test_active_exact_scope_connection_executes_bounded_read(runtime_state):
    database, owner_id, connection, connections, manifests, adapters = runtime_state
    _activate_test_connection(database, connection)
    adapter = FakeReadAdapter()
    adapters.register("catalog", adapter)
    runtime = ReadOnlyIntegrationRuntime(
        manifests=manifests, adapters=adapters, connections=connections
    )
    result = asyncio.run(runtime.execute(
        owner_id, connection["id"], "catalog.search", {"query": "hello"}
    ))
    assert result == {"items": ["one"]}
    assert adapter.calls == 1


def test_runtime_rejects_credential_like_adapter_output(runtime_state):
    database, owner_id, connection, connections, manifests, adapters = runtime_state
    _activate_test_connection(database, connection)
    adapters.register("catalog", FakeReadAdapter({"items": ["one"], "access_token": "secret"}))
    runtime = ReadOnlyIntegrationRuntime(
        manifests=manifests, adapters=adapters, connections=connections
    )
    with pytest.raises(ValueError, match="credential-like"):
        asyncio.run(runtime.execute(
            owner_id, connection["id"], "catalog.search", {"query": "hello"}
        ))


def test_runtime_rejects_unregistered_tool_and_invalid_arguments(runtime_state):
    _, owner_id, connection, connections, manifests, adapters = runtime_state
    adapters.register("catalog", FakeReadAdapter())
    runtime = ReadOnlyIntegrationRuntime(
        manifests=manifests, adapters=adapters, connections=connections
    )
    with pytest.raises(LookupError):
        asyncio.run(runtime.execute(owner_id, connection["id"], "catalog.unknown", {}))
    with pytest.raises(ValueError):
        asyncio.run(runtime.execute(owner_id, connection["id"], "catalog.search", {"unexpected": True}))

class SlowReadAdapter:
    async def execute(self, *, user_id, connection_id, tool_id, arguments):
        await asyncio.sleep(0.05)
        return {"items": ["late"]}


def test_runtime_enforces_adapter_timeout(runtime_state):
    database, owner_id, connection, connections, manifests, adapters = runtime_state
    _activate_test_connection(database, connection)
    adapters.register("catalog", SlowReadAdapter())
    runtime = ReadOnlyIntegrationRuntime(
        manifests=manifests, adapters=adapters, connections=connections,
        timeout_seconds=0.001,
    )
    with pytest.raises(TimeoutError):
        asyncio.run(runtime.execute(
            owner_id, connection["id"], "catalog.search", {"query": "hello"}
        ))


def test_runtime_enforces_serialized_output_bound(runtime_state):
    database, owner_id, connection, connections, manifests, adapters = runtime_state
    _activate_test_connection(database, connection)
    adapters.register("catalog", FakeReadAdapter({"items": ["x" * 5000]}))
    runtime = ReadOnlyIntegrationRuntime(
        manifests=manifests, adapters=adapters, connections=connections,
        max_output_bytes=1024,
    )
    with pytest.raises(ValueError, match="output exceeds"):
        asyncio.run(runtime.execute(
            owner_id, connection["id"], "catalog.search", {"query": "hello"}
        ))
