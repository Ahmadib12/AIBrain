from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentTask:
    task_id: str
    goal: str
    allowed_capabilities: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    deadline_seconds: float


class SpecializedAgent(ABC):
    @property
    @abstractmethod
    def agent_id(self) -> str:
        ...

    @abstractmethod
    async def execute(self, task: AgentTask) -> dict[str, Any]:
        ...
