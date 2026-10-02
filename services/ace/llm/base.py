"""Provider-agnostic LLM interface for the ACE agent layer.

Agents depend on :class:`LLMProvider` only. Swapping the reasoning backend
(Nebius Token Factory today, any OpenAI-compatible endpoint tomorrow) must never
require touching agent code — that is the whole point of this boundary.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMProvider(ABC):
    """Abstract base for every LLM backend used by the ACE+RHG agents."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Stable identifier used in audit trails and metrics labels."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier used in audit trails."""

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """Run a single chat completion and return the first choice."""
