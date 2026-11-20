from backend.app.agli.registry import LanguageRegistry
from backend.app.agli.schemas import LanguageEntry


class AGLI:
    """Interface for AIBrain's Global Language Intelligence subsystem."""

    def __init__(self, registry: LanguageRegistry) -> None:
        self.registry = registry

    def list_languages(self) -> tuple[LanguageEntry, ...]:
        return self.registry.list_languages()

    def lookup(self, code: str) -> LanguageEntry | None:
        if not code or not code.strip():
            return None
        return self.registry.get(code.strip())
