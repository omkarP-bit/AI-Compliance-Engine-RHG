"""NVIDIA Nemotron served through Nebius Token Factory.

Nebius exposes an OpenAI-compatible ``/v1/chat/completions`` endpoint, so no
Nebius-specific SDK is required — just an HTTP call with a bearer token.
"""

from __future__ import annotations

import os

import httpx

from ace.llm.base import LLMMessage, LLMProvider, LLMResponse

DEFAULT_BASE_URL = "https://api.studio.nebius.ai/v1"
DEFAULT_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"
REQUEST_TIMEOUT_SECONDS = 60.0


class NebiusConfigurationError(RuntimeError):
    """Raised when a Nebius call is attempted without an API key configured."""


class NebiusProvider(LLMProvider):
    """LLM provider backed by Nemotron on Nebius Token Factory.

    Construction never fails on a missing key: agents are instantiated at import
    time in several modules, and a hard ``KeyError`` there would take down the
    whole service in environments that do not use agentic mode. The missing-key
    error is deferred to :meth:`complete`, where it is actionable.
    """

    def __init__(self) -> None:
        self._api_key = os.environ.get("NEBIUS_API_KEY", "").strip()
        self._base_url = os.environ.get("NEBIUS_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
        self._model = os.environ.get("NEMOTRON_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    @property
    def provider_name(self) -> str:
        return "nebius"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    def _require_api_key(self) -> str:
        if not self._api_key:
            raise NebiusConfigurationError(
                "NEBIUS_API_KEY is not set. Agentic mode needs a Nebius Token "
                "Factory key, or point MODEL_PROVIDER at another provider."
            )
        return self._api_key

    async def complete(
        self,
        messages: list[LLMMessage],
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> LLMResponse:
        api_key = self._require_api_key()
        payload = {
            "model": self._model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return LLMResponse(
            content=self._extract_content(data),
            model=self._model,
            provider="nebius",
            prompt_tokens=self._usage(data, "prompt_tokens"),
            completion_tokens=self._usage(data, "completion_tokens"),
        )

    @staticmethod
    def _extract_content(data: dict) -> str:
        choices = data.get("choices") or []
        if not choices:
            return ""
        message = choices[0].get("message") or {}
        return message.get("content") or ""

    @staticmethod
    def _usage(data: dict, key: str) -> int:
        return (data.get("usage") or {}).get(key, 0) or 0
