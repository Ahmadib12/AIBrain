from backend.app.config import Settings, get_settings
from backend.app.agli.engine_registry import LanguageEngineRegistry
from backend.app.auth.webauthn_service import WebAuthnService
from backend.app.persistence.database import Database
from backend.app.persistence.devices import DeviceRepository
from backend.app.devices.proof import DeviceProofRepository
from backend.app.persistence.agents import AgentRepository
from backend.app.persistence.agent_control import AgentControlRepository
from backend.app.persistence.agent_execution import AgentExecutionRepository
from backend.app.persistence.identity import IdentityRepository
from backend.app.persistence.integration_connections import IntegrationConnectionRepository
from backend.app.persistence.learning import BehavioralLearningRepository
from backend.app.persistence.memory import MemoryRepository
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.persistence.webauthn import WebAuthnRepository
from backend.app.tools.integrations import IntegrationRegistry
from backend.app.tools.integration_vault import IntegrationSecretVault
from backend.app.tools.integration_lifecycle import (
    IntegrationConnectionLifecycle,
    ProviderVerifierRegistry,
)
from backend.app.tools.integration_runtime import (
    IntegrationAdapterRegistry,
    ReadOnlyIntegrationRuntime,
)
from backend.app.tools.integration_orchestrator import IntegrationAgentRunOrchestrator


class AppState:
    def __init__(self, settings: Settings) -> None:
        self.database = Database(settings.database_url)
        # Runtime engines are registered only by trusted server composition.
        self.agli_engines = LanguageEngineRegistry()
        self.devices = DeviceRepository(self.database)
        self.device_proofs = DeviceProofRepository(self.database)
        self.identity = IdentityRepository(
            self.database,
            session_ttl_seconds=settings.session_ttl_seconds,
        )
        self.memory = MemoryRepository(self.database)
        self.learning = BehavioralLearningRepository(self.database)
        self.agents = AgentRepository(self.database)
        self.agent_control = AgentControlRepository(self.database)
        self.agent_execution = AgentExecutionRepository(self.database)
        self.integration_connections = IntegrationConnectionRepository(self.database)
        vault_key = (
            settings.integration_vault_key_b64.get_secret_value()
            if settings.integration_vault_key_b64 is not None else None
        )
        self.integration_vault = IntegrationSecretVault(self.database, vault_key)
        self.integration_provider_verifiers = ProviderVerifierRegistry()
        self.integration_connection_lifecycle = IntegrationConnectionLifecycle(
            connections=self.integration_connections,
            vault=self.integration_vault,
            verifiers=self.integration_provider_verifiers,
        )
        self.integrations = IntegrationRegistry()
        self.integration_adapters = IntegrationAdapterRegistry()
        self.integration_runtime = ReadOnlyIntegrationRuntime(
            manifests=self.integrations,
            adapters=self.integration_adapters,
            connections=self.integration_connections,
        )
        self.integration_orchestrator = IntegrationAgentRunOrchestrator(
            execution=self.agent_execution,
            runtime=self.integration_runtime,
        )
        suite_trust = None
        if settings.conformance_suite_authority_public_key_b64 is not None:
            import base64
            suite_trust = {
                "public_key": base64.b64decode(
                    settings.conformance_suite_authority_public_key_b64,
                    validate=True,
                ),
                "authority_key_id": settings.conformance_suite_authority_key_id,
                "expected_suite_id": settings.conformance_suite_expected_id,
                "expected_suite_version": settings.conformance_suite_expected_version,
            }
        self.tool_requests = ToolRequestRepository(
            self.database, conformance_suite_trust=suite_trust
        )
        self.webauthn = WebAuthnRepository(self.database)
        self.webauthn_service = WebAuthnService(
            repository=self.webauthn,
            tool_requests=self.tool_requests,
            settings=settings,
        )


_app_state: AppState | None = None


def get_app_state(settings: Settings | None = None) -> AppState:
    global _app_state
    if _app_state is None:
        resolved_settings = settings if settings is not None else get_settings()
        _app_state = AppState(resolved_settings)
    return _app_state


def set_app_state(state: AppState) -> None:
    global _app_state
    previous = _app_state
    if previous is state:
        return
    if previous is not None:
        previous.database.shutdown()
    _app_state = state


def reset_app_state() -> None:
    global _app_state
    state = _app_state
    _app_state = None
    if state is not None:
        state.database.shutdown()
