from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class AgentResult:
    agent_name: str
    confidence: float
    enriched_findings: list[dict]
    recommendations: list[str]
    escalate: bool
    context: dict[str, Any]


class BaseAgent(ABC):
    name: str

    @abstractmethod
    async def run(self, artifact: dict, findings: list[dict], context: dict) -> AgentResult:
        ...
