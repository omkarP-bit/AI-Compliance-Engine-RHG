"""Factory that resolves the configured LLM provider."""

from __future__ import annotations

import os

from ace.llm.base import LLMProvider
from ace.llm.nebius import NebiusProvider

#: Registered providers, keyed by the name accepted in ``MODEL_PROVIDER``.
PROVIDERS: dict[str, type[LLMProvider]] = {
    "nebius": NebiusProvider,
}

DEFAULT_PROVIDER = "nebius"


def get_provider(provider_name: str | None = None) -> LLMProvider:
    """Instantiate a provider by name, defaulting to ``MODEL_PROVIDER``/nebius."""
    name = (provider_name or os.environ.get("MODEL_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    try:
        provider_cls = PROVIDERS[name]
    except KeyError as exc:
        supported = ", ".join(sorted(PROVIDERS))
        raise ValueError(f"Unknown LLM provider: {name!r}. Supported: {supported}") from exc
    return provider_cls()


def supported_providers() -> list[str]:
    """Names accepted by :func:`get_provider`."""
    return sorted(PROVIDERS)
