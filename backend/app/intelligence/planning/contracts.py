"""Provider-independent, validated contracts for bounded intelligence planning.

These contracts describe intent and proposed work only. They do not authorize or
execute actions; execution must pass through the existing policy and tool
authorization lifecycle.
"""
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.intelligence.schemas import contains_credential_content


class IntentKind(str, Enum):
    INFORM = "inform"
    CREATE = "create"
    ANALYZE = "analyze"
    TRANSFORM = "transform"
    RETRIEVE = "retrieve"
    CONTROL = "control"
    UNKNOWN = "unknown"


class PlanTaskKind(str, Enum):
    REASON = "reason"
    RETRIEVE = "retrieve"
    GENERATE = "generate"
    TRANSFORM = "transform"
    VALIDATE = "validate"
    REQUEST_INPUT = "request_input"


def _validate_public_text(value: str, *, label: str) -> str:
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    if contains_credential_content(value):
        raise ValueError(f"{label} must not contain credentials")
    return value


def _validate_identifier(value: str, *, label: str) -> str:
    _validate_public_text(value, label=label)
    if value != value.strip():
        raise ValueError(f"{label} must not contain surrounding whitespace")
    return value


class IntentContract(BaseModel):
    """A normalized interpretation of the user's request, not a permission."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    intent_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=100)
    kind: IntentKind
    summary: str = Field(min_length=1, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
    ambiguities: tuple[str, ...] = Field(default_factory=tuple, max_length=10)

    @field_validator("intent_id")
    @classmethod
    def validate_intent_id(cls, value: str) -> str:
        return _validate_identifier(value, label="Intent ID")

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return _validate_public_text(value, label="Intent summary")

    @field_validator("ambiguities")
    @classmethod
    def validate_ambiguities(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _validate_public_text(value, label="Intent ambiguity")
            for value in values
        )


class GoalContract(BaseModel):
    """A user-outcome definition against which a proposed plan can be checked."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    goal_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1_000)
    success_criteria: tuple[str, ...] = Field(min_length=1, max_length=10)
    constraints: tuple[str, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("goal_id")
    @classmethod
    def validate_goal_id(cls, value: str) -> str:
        return _validate_identifier(value, label="Goal ID")

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _validate_public_text(value, label="Goal description")

    @field_validator("success_criteria", "constraints")
    @classmethod
    def validate_text_items(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _validate_public_text(value, label="Goal requirement")
            for value in values
        )


class PlannedTask(BaseModel):
    """One bounded proposed step; capability IDs are references, not grants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
    kind: PlanTaskKind
    description: str = Field(min_length=1, max_length=500)
    capability_id: str | None = Field(default=None, min_length=1, max_length=100)
    depends_on: tuple[str, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("task_id")
    @classmethod
    def validate_task_id(cls, value: str) -> str:
        return _validate_identifier(value, label="Task ID")

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _validate_public_text(value, label="Task description")

    @field_validator("capability_id")
    @classmethod
    def validate_capability_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not normalized or not all(
            char.isalnum() or char in "_-" for char in normalized
        ):
            raise ValueError("Capability ID contains unsupported characters")
        return normalized

    @field_validator("depends_on")
    @classmethod
    def validate_dependencies(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("Task dependencies must be unique")
        return tuple(
            _validate_identifier(value, label="Task dependency")
            for value in values
        )


class TaskPlanContract(BaseModel):
    """An ordered, bounded DAG of proposed work; never an execution approval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=100)
    goal: GoalContract
    tasks: tuple[PlannedTask, ...] = Field(min_length=1, max_length=20)
    rationale: str = Field(min_length=1, max_length=1_000)

    @field_validator("plan_id")
    @classmethod
    def validate_plan_id(cls, value: str) -> str:
        return _validate_identifier(value, label="Plan ID")

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        return _validate_public_text(value, label="Plan rationale")

    @model_validator(mode="after")
    def validate_task_graph(self) -> "TaskPlanContract":
        task_ids = [task.task_id for task in self.tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("Task IDs must be unique")

        seen: set[str] = set()
        for task in self.tasks:
            for dependency in task.depends_on:
                if dependency not in seen:
                    raise ValueError(
                        "Dependencies must reference an earlier task in the plan"
                    )
            seen.add(task.task_id)
        return self
