from backend.app.config import Settings, get_settings
from backend.app.auth.webauthn_service import WebAuthnService
from backend.app.persistence.database import Database
from backend.app.persistence.agents import AgentRepository
from backend.app.persistence.identity import IdentityRepository
from backend.app.persistence.learning import BehavioralLearningRepository
from backend.app.persistence.memory import MemoryRepository
from backend.app.persistence.tool_requests import ToolRequestRepository
from backend.app.persistence.webauthn import WebAuthnRepository


class AppState:
    def __init__(self, settings: Settings) -> None:
        self.database = Database(settings.database_url)
        self.identity = IdentityRepository(
            self.database,
            session_ttl_seconds=settings.session_ttl_seconds,
        )
        self.memory = MemoryRepository(self.database)
        self.learning = BehavioralLearningRepository(self.database)
        self.agents = AgentRepository(self.database)
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
