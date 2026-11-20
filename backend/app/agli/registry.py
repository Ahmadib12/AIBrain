from backend.app.agli.schemas import (
    CapabilityProfile,
    DialectMetadata,
    LanguageCapability,
    LanguageEntry,
    ScriptMetadata,
)


_REGISTERED = CapabilityProfile()


def _all_registered() -> dict[LanguageCapability, CapabilityProfile]:
    return {capability: _REGISTERED for capability in LanguageCapability}


class LanguageRegistry:
    def __init__(self, entries: tuple[LanguageEntry, ...]) -> None:
        self._entries = {entry.code: entry for entry in entries}

    def list_languages(self) -> tuple[LanguageEntry, ...]:
        return tuple(sorted(self._entries.values(), key=lambda entry: entry.code))

    def get(self, code: str) -> LanguageEntry | None:
        return self._entries.get(code.lower())

    def validate_entry(self, entry: LanguageEntry) -> LanguageEntry:
        if not entry.capabilities:
            raise ValueError("A language must have an explicit capability profile")
        return entry


language_registry = LanguageRegistry(
    (
        LanguageEntry(
            code="en",
            name="English",
            native_name="English",
            script=ScriptMetadata(code="Latn", name="Latin", direction="ltr"),
            dialects=(
                DialectMetadata(code="en-US", name="American English"),
                DialectMetadata(code="en-GB", name="British English"),
            ),
            capabilities=_all_registered(),
        ),
        LanguageEntry(
            code="es",
            name="Spanish",
            native_name="Español",
            script=ScriptMetadata(code="Latn", name="Latin", direction="ltr"),
            dialects=(
                DialectMetadata(code="es-ES", name="Castilian Spanish"),
                DialectMetadata(code="es-MX", name="Mexican Spanish"),
            ),
            capabilities=_all_registered(),
        ),
        LanguageEntry(
            code="fr",
            name="French",
            native_name="Français",
            script=ScriptMetadata(code="Latn", name="Latin", direction="ltr"),
            dialects=(DialectMetadata(code="fr-FR", name="French (France)"),),
            capabilities=_all_registered(),
        ),
        LanguageEntry(
            code="ar",
            name="Arabic",
            native_name="العربية",
            script=ScriptMetadata(code="Arab", name="Arabic", direction="rtl"),
            dialects=(
                DialectMetadata(code="ar-SA", name="Saudi Arabic"),
                DialectMetadata(code="ar-EG", name="Egyptian Arabic"),
            ),
            capabilities=_all_registered(),
        ),
    )
)
