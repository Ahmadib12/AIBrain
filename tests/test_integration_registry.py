import pytest

from backend.app.tools.contracts import ToolContract, ToolRisk
from backend.app.tools.integrations import (
    IntegrationManifest,
    IntegrationRegistry,
    IntegrationTool,
)


def _contract(tool_id: str = "web.search") -> ToolContract:
    return ToolContract(
        tool_id=tool_id,
        name="Search",
        description="Read-only search",
        risk=ToolRisk.READ_ONLY,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 200}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


def _manifest() -> IntegrationManifest:
    return IntegrationManifest(
        integration_id="web",
        name="Web search",
        description="Search provider connector",
        version="1",
        tools=(
            IntegrationTool(
                contract=_contract(),
                required_scopes=("web.search",),
            ),
        ),
    )


def test_registry_lists_safe_catalog_and_resolves_tool():
    registry = IntegrationRegistry()
    registry.register(_manifest())

    catalog = registry.catalog()
    assert len(catalog) == 1
    assert catalog[0]["integration_id"] == "web"
    assert catalog[0]["tools"][0]["tool_id"] == "web.search"
    assert catalog[0]["tools"][0]["risk"] == "read_only"
    assert catalog[0]["tools"][0]["required_scopes"] == ["web.search"]

    resolved = registry.resolve_tool("web.search")
    assert resolved is not None
    integration_id, item = resolved
    assert integration_id == "web"
    assert item.contract.tool_id == "web.search"


def test_registry_rejects_duplicate_integration_ids_and_allows_distinct_namespaces():
    registry = IntegrationRegistry()
    registry.register(_manifest())
    with pytest.raises(ValueError):
        registry.register(_manifest())

    other = IntegrationManifest(
        integration_id="other",
        name="Other",
        description="Duplicate tool namespace test",
        version="1",
        tools=(IntegrationTool(_contract("other.search"), ("other.search",)),),
    )
    registry.register(other)
    # Valid manifests must namespace tool IDs by integration ID, so a
    # cross-integration collision cannot be constructed. Distinct namespaces
    # remain independently registrable.
    assert registry.resolve_tool("web.search") is not None
    assert registry.resolve_tool("other.search") is not None


def test_manifest_rejects_state_changing_and_unscoped_tool_ids():
    state_change = ToolContract(
        tool_id="notes.write",
        name="Write note",
        description="Changes a note",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
    )
    with pytest.raises(ValueError):
        IntegrationTool(state_change, ("notes.write",))

    with pytest.raises(ValueError):
        IntegrationManifest(
            integration_id="notes",
            name="Notes",
            description="Notes integration",
            version="1",
            tools=(IntegrationTool(_contract("unscoped.search"), ()),),
        )


def test_manifest_rejects_invalid_and_duplicate_scopes():
    with pytest.raises(ValueError):
        IntegrationTool(_contract(), ())
    with pytest.raises(ValueError):
        IntegrationTool(_contract(), ("web.search", "web.search"))
    with pytest.raises(ValueError):
        IntegrationTool(_contract(), ("../secrets",))


def test_registry_returns_defensive_copies():
    registry = IntegrationRegistry()
    manifest = _manifest()
    registry.register(manifest)

    retrieved = registry.get("web")
    assert retrieved is not None
    retrieved.tools[0].contract.input_schema["properties"]["query"]["maxLength"] = 9999

    again = registry.resolve_tool("web.search")
    assert again is not None
    assert again[1].contract.input_schema["properties"]["query"]["maxLength"] == 200
