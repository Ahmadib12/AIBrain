import pytest
from pydantic import ValidationError

from backend.app.agli.core import AGLI
from backend.app.agli.registry import language_registry
from backend.app.agli.schemas import (
    CapabilityProfile,
    DialectMetadata,
    LanguageCapability,
    LanguageEntry,
    ScriptMetadata,
)


def test_registry_contains_representative_languages() -> None:
    codes = {entry.code for entry in language_registry.list_languages()}
    assert {"en", "es", "fr", "ar"} <= codes


def test_language_lookup_is_case_insensitive() -> None:
    assert language_registry.get("EN").code == "en"


def test_unknown_language_returns_none() -> None:
    assert language_registry.get("xx") is None


def test_capability_profiles_are_explicit_and_registered() -> None:
    english = language_registry.get("en")
    assert english is not None
    assert set(english.capabilities) == set(LanguageCapability)
    assert all(
        profile.status.value == "registered"
        for profile in english.capabilities.values()
    )


def test_dialect_metadata_is_available() -> None:
    english = language_registry.get("en")
    assert english is not None
    assert DialectMetadata(code="en-US", name="American English") in english.dialects


def test_invalid_language_code_is_rejected() -> None:
    with pytest.raises(ValidationError):
        LanguageEntry(
            code="bad code",
            name="Invalid",
            native_name="Invalid",
            script=ScriptMetadata(code="Latn", name="Latin", direction="ltr"),
            capabilities={
                capability: CapabilityProfile()
                for capability in LanguageCapability
            },
        )


def test_blank_native_name_is_rejected() -> None:
    with pytest.raises(ValidationError):
        LanguageEntry(
            code="xx",
            name="Unknown",
            native_name=" ",
            script=ScriptMetadata(code="Latn", name="Latin", direction="ltr"),
            capabilities={
                capability: CapabilityProfile()
                for capability in LanguageCapability
            },
        )


def test_agli_lookup_rejects_blank_input() -> None:
    agli = AGLI(language_registry)
    assert agli.lookup("") is None
    assert agli.lookup("   ") is None
