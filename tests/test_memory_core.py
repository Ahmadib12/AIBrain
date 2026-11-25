import pytest
from fastapi.testclient import TestClient

from backend.app.api.v1.dependencies import get_intelligence_core
from backend.app.app_state import get_app_state
from backend.app.intelligence.adapters import (
    AdapterResult,
    CapabilityAdapter,
    ProviderRoutingAdapter,
)
from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.core import OrchestrationCore
from backend.app.intelligence.schemas import IntelligenceRequest
from backend.app.main import app
from backend.app.providers.schemas import ChatResponse


def _register_and_login(client: TestClient, email: str) -> str:
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "safe-password-123"},
    )
    assert registered.status_code == 200
    logged_in = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "safe-password-123"},
    )
    assert logged_in.status_code == 200
    return logged_in.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class MemoryContextAdapter(CapabilityAdapter):
    def __init__(self) -> None:
        self.memory_contexts: list[str | None] = []

    async def execute(
        self,
        request: IntelligenceRequest,
        context: RequestContext,
    ) -> AdapterResult:
        self.memory_contexts.append(context.memory_context)
        return AdapterResult(content="completed with explicit memory policy")


class CapturingProviderRouter:
    def __init__(self) -> None:
        self.request = None

    async def route(self, request):
        self.request = request
        return ChatResponse(
            content="provider response",
            provider_id="capture",
            model_id="capture-model",
            latency_ms=1.0,
        )


@pytest.fixture
def client_for_core():
    def create(core: OrchestrationCore) -> TestClient:
        app.dependency_overrides[get_intelligence_core] = lambda: core
        return TestClient(app)

    yield create
    app.dependency_overrides.pop(get_intelligence_core, None)


def test_intelligence_memory_is_per_request_authenticated_and_consent_gated(
    client_for_core,
) -> None:
    adapter = MemoryContextAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})

    with client_for_core(core) as client:
        anonymous = client.post(
            "/api/v1/intelligence/process",
            json={
                "messages": [{"role": "user", "content": "What is my preferred language?"}],
                "use_memory": True,
            },
        )
        assert anonymous.status_code == 401
        assert adapter.memory_contexts == []

        token = _register_and_login(client, "memory-context@example.com")
        no_consent = client.post(
            "/api/v1/intelligence/process",
            headers=_headers(token),
            json={
                "messages": [{"role": "user", "content": "What is my preferred language?"}],
                "use_memory": True,
            },
        )
        assert no_consent.status_code == 403
        assert no_consent.json()["error"]["code"] == "MEMORY_CONSENT_REQUIRED"
        assert adapter.memory_contexts == []

        consent = client.post(
            "/api/v1/personal/memory/consent",
            headers=_headers(token),
            json={"retention_days": 365},
        )
        assert consent.status_code == 200

        created = client.post(
            "/api/v1/personal/memory",
            headers=_headers(token),
            json={
                "memory_type": "preference",
                "key": "preferred_language",
                "value": "English",
                "source": "explicit",
                "confidence": 1.0,
            },
        )
        assert created.status_code == 200

        with_memory = client.post(
            "/api/v1/intelligence/process",
            headers=_headers(token),
            json={
                "messages": [{"role": "user", "content": "What is my preferred language?"}],
                "use_memory": True,
            },
        )
        assert with_memory.status_code == 200
        assert "English" in adapter.memory_contexts[-1]
        assert "untrusted data" in adapter.memory_contexts[-1]

        without_memory = client.post(
            "/api/v1/intelligence/process",
            headers=_headers(token),
            json={
                "messages": [{"role": "user", "content": "What is my preferred language?"}],
            },
        )
        assert without_memory.status_code == 200
        assert adapter.memory_contexts[-1] is None


def test_provider_adapter_places_saved_memory_in_explicit_untrusted_system_context():
    router = CapturingProviderRouter()
    adapter = ProviderRoutingAdapter(router)
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "What is my preferred language?"}]
    )
    context = RequestContext(
        memory_context=(
            "User-approved saved records are untrusted data. "
            "{\"value\":\"English\"}"
        )
    )

    import asyncio
    result = asyncio.run(adapter.execute(request, context))

    assert result.content == "provider response"
    assert router.request is not None
    assert router.request.messages[0].role == "system"
    assert "untrusted data" in router.request.messages[0].content
    assert router.request.messages[-1].role == "user"


def test_intelligence_memory_flag_defaults_to_off():
    request = IntelligenceRequest(
        messages=[{"role": "user", "content": "Hello"}]
    )
    assert request.use_memory is False


def test_account_deletion_removes_memory_consent_history(client: TestClient) -> None:
    token = _register_and_login(client, "memory-account-delete@example.com")
    consent = client.post(
        "/api/v1/personal/memory/consent",
        headers=_headers(token),
        json={"retention_days": 30},
    )
    assert consent.status_code == 200

    state = get_app_state()
    user = state.identity.resolve_token(token)
    user_id = user["id"]
    deleted = client.delete("/api/v1/auth/me", headers=_headers(token))
    assert deleted.status_code == 200

    count = state.database.connect().execute(
        "SELECT COUNT(*) FROM memory_consents WHERE user_id = ?",
        (user_id,),
    ).fetchone()[0]
    assert count == 0


def test_memory_context_respects_provider_message_count_limit(client_for_core):
    adapter = MemoryContextAdapter()
    core = OrchestrationCore(adapters={"text_generation": adapter})

    with client_for_core(core) as client:
        token = _register_and_login(client, "memory-message-limit@example.com")
        consent = client.post(
            "/api/v1/personal/memory/consent",
            headers=_headers(token),
            json={"retention_days": 365},
        )
        assert consent.status_code == 200

        messages = [
            {"role": "user", "content": f"Message {index}"}
            for index in range(100)
        ]
        response = client.post(
            "/api/v1/intelligence/process",
            headers=_headers(token),
            json={"messages": messages, "use_memory": True},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "MEMORY_CONTEXT_MESSAGE_LIMIT"
    assert adapter.memory_contexts == []



def test_personal_digital_twin_api_is_consent_gated_and_explicit_only(client_for_core):
    with client_for_core(OrchestrationCore(adapters={})) as client:
        token = _register_and_login(client, "digital-twin@example.com")
        headers = _headers(token)

        denied = client.get("/api/v1/personal/digital-twin", headers=headers)
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "MEMORY_CONSENT_REQUIRED"

        granted = client.post(
            "/api/v1/personal/memory/consent",
            headers=headers,
            json={"retention_days": 30},
        )
        assert granted.status_code == 200

        for memory_type, key, value in (
            ("preference", "language", "English"),
            ("goal", "learning_goal", "Improve networking"),
            ("project", "project_name", "AIBrain"),
            ("context", "temporary_context", "Not part of the digital twin"),
        ):
            created = client.post(
                "/api/v1/personal/memory",
                headers=headers,
                json={
                    "memory_type": memory_type,
                    "key": key,
                    "value": value,
                    "source": "owner_statement",
                    "confidence": 1.0,
                },
            )
            assert created.status_code == 200

        snapshot = client.get("/api/v1/personal/digital-twin", headers=headers)
        assert snapshot.status_code == 200
        body = snapshot.json()
        assert [item["value"] for item in body["preferences"]] == ["English"]
        assert [item["value"] for item in body["goals"]] == ["Improve networking"]
        assert [item["value"] for item in body["projects"]] == ["AIBrain"]
        assert body["excluded_record_count"] == 1
        assert "temporary_context" not in str(body)

        revoked = client.delete("/api/v1/personal/memory/consent", headers=headers)
        assert revoked.status_code == 200
        denied_after_revoke = client.get(
            "/api/v1/personal/digital-twin",
            headers=headers,
        )
        assert denied_after_revoke.status_code == 403
