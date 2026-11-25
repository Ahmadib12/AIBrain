import pytest

from backend.app.intelligence.digital_twin import PersonalDigitalTwinAssembler


class FakeMemoryRepository:
    def __init__(self, *, enabled=True, records=()):
        self.enabled = enabled
        self.records = tuple(records)

    def approved_digital_twin_records(self, user_id):
        if not self.enabled:
            raise PermissionError("Active personal-memory consent is required")
        return {"policy_version": 3, "records": self.records}


def record(memory_type, index):
    return {
        "id": f"memory-{index}",
        "memory_type": memory_type,
        "key": f"key-{index}",
        "value": {"explicit": True, "index": index},
        "source": "owner_statement",
        "confidence": 1.0,
        "created_at": "2026-11-25T00:00:00+00:00",
        "updated_at": "2026-11-25T00:00:00+00:00",
        "expires_at": None,
    }


def test_digital_twin_requires_active_explicit_memory_consent():
    with pytest.raises(PermissionError, match="Active personal-memory consent"):
        PersonalDigitalTwinAssembler().assemble(
            FakeMemoryRepository(enabled=False),
            user_id="owner-a",
        )


def test_digital_twin_contains_only_explicit_preferences_goals_and_projects():
    repository = FakeMemoryRepository(records=(
        record("preference", 1),
        record("goal", 2),
        record("project", 3),
        record("context", 4),
    ))
    result = PersonalDigitalTwinAssembler().assemble(
        repository,
        user_id="owner-a",
    )
    assert [item.memory_id for item in result.preferences] == ["memory-1"]
    assert [item.memory_id for item in result.goals] == ["memory-2"]
    assert [item.memory_id for item in result.projects] == ["memory-3"]
    assert result.excluded_record_count == 1
    assert result.consent_policy_version == 3


def test_digital_twin_is_owner_scoped_and_bounded_per_category():
    records = tuple(record("preference", index) for index in range(60))
    result = PersonalDigitalTwinAssembler().assemble(
        FakeMemoryRepository(records=records),
        user_id="owner-a",
    )
    assert len(result.preferences) == 50
    assert result.excluded_record_count == 10
    assert all(item.source == "owner_statement" for item in result.preferences)
    assert all(item.confidence == 1.0 for item in result.preferences)


def test_digital_twin_never_invents_inferred_records():
    result = PersonalDigitalTwinAssembler().assemble(
        FakeMemoryRepository(records=(record("goal", 1),)),
        user_id="owner-a",
    )
    assert len(result.goals) == 1
    assert result.goals[0].value == {"explicit": True, "index": 1}
    assert result.goals[0].record_kind == "goal"
