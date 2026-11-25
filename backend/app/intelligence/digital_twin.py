"""Read-only personal digital-twin projection from explicit owner memory.

This is not an inferred psychological profile. It exposes only explicit,
owner-approved preference, goal, and project records while memory consent is
active. Transient context and behavioral observations are excluded.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.persistence.memory import MemoryRepository


class DigitalTwinRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_id: str
    key: str = Field(min_length=1, max_length=200)
    value: Any
    source: str = Field(min_length=1, max_length=100)
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: str
    updated_at: str
    expires_at: str | None = None
    record_kind: str


class PersonalDigitalTwinSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    generated_at: str
    consent_policy_version: int
    preferences: tuple[DigitalTwinRecord, ...] = Field(max_length=50)
    goals: tuple[DigitalTwinRecord, ...] = Field(max_length=50)
    projects: tuple[DigitalTwinRecord, ...] = Field(max_length=50)
    excluded_record_count: int = Field(ge=0)


class PersonalDigitalTwinAssembler:
    MAX_RECORDS = 50

    def assemble(
        self,
        repository: MemoryRepository,
        *,
        user_id: str,
    ) -> PersonalDigitalTwinSnapshot:
        consent = repository.consent_status(user_id)
        if not consent["enabled"]:
            raise PermissionError("Active personal-memory consent is required")
        records = repository.list(user_id)
        buckets: dict[str, list[DigitalTwinRecord]] = {
            "preference": [],
            "goal": [],
            "project": [],
        }
        excluded = 0
        for record in records:
            kind = record.get("memory_type")
            if kind not in buckets:
                excluded += 1
                continue
            if len(buckets[kind]) >= self.MAX_RECORDS:
                excluded += 1
                continue
            buckets[kind].append(DigitalTwinRecord(
                memory_id=record["id"],
                key=record["key"],
                value=record["value"],
                source=record["source"],
                confidence=record["confidence"],
                created_at=record["created_at"],
                updated_at=record["updated_at"],
                expires_at=record["expires_at"],
                record_kind=kind,
            ))
        return PersonalDigitalTwinSnapshot(
            generated_at=datetime.now(timezone.utc).isoformat(),
            consent_policy_version=consent["policy_version"],
            preferences=tuple(buckets["preference"]),
            goals=tuple(buckets["goal"]),
            projects=tuple(buckets["project"]),
            excluded_record_count=excluded,
        )
