import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ace.llm.base import LLMMessage, LLMProvider, LLMResponse
from ace.llm.nebius import NebiusConfigurationError, NebiusProvider
from ace.llm.provider import get_provider, supported_providers


def _mock_client(response_json: dict) -> AsyncMock:
    """An ``httpx.AsyncClient`` stand-in usable with ``async with``."""
    http_response = MagicMock()
    http_response.json.return_value = response_json
    http_response.raise_for_status = MagicMock()

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    client.post = AsyncMock(return_value=http_response)
    return client


class _StubProvider(LLMProvider):
    @property
    def provider_name(self) -> str:
        return "stub"

    @property
    def model_name(self) -> str:
        return "stub-model"

    async def complete(self, messages, max_tokens=1024, temperature=0.2) -> LLMResponse:
        return LLMResponse(content="", model=self.model_name, provider=self.provider_name)


@pytest.mark.asyncio
class TestNebiusProvider:
    async def test_construction_never_raises_without_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            provider = NebiusProvider()
            assert provider.is_configured is False
            assert provider.provider_name == "nebius"
            assert provider.model_name

    async def test_complete_raises_when_key_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            provider = NebiusProvider()
            with pytest.raises(NebiusConfigurationError, match="NEBIUS_API_KEY"):
                await provider.complete([LLMMessage(role="user", content="hi")])

    async def test_complete_posts_bearer_token_and_parses_response(self):
        client = _mock_client(
            {
                "choices": [{"message": {"content": "hello"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3},
            }
        )
        with patch.dict(os.environ, {"NEBIUS_API_KEY": "secret-key"}):
            with patch("httpx.AsyncClient", return_value=client):
                provider = NebiusProvider()
                out = await provider.complete(
                    [LLMMessage(role="system", content="s"), LLMMessage(role="user", content="q")],
                    max_tokens=64,
                    temperature=0.1,
                )

        assert out.content == "hello"
        assert out.provider == "nebius"
        assert (out.prompt_tokens, out.completion_tokens) == (7, 3)

        url = client.post.call_args[0][0]
        assert url == "https://api.studio.nebius.ai/v1/chat/completions"
        headers = client.post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer secret-key"
        payload = client.post.call_args[1]["json"]
        assert payload["max_tokens"] == 64
        assert payload["temperature"] == 0.1
        assert [m["role"] for m in payload["messages"]] == ["system", "user"]

    async def test_complete_honours_base_url_and_model_overrides(self):
        client = _mock_client({"choices": [{"message": {"content": "x"}}]})
        with patch.dict(
            os.environ,
            {
                "NEBIUS_API_KEY": "k",
                "NEBIUS_BASE_URL": "https://gateway.internal/v1/",
                "NEMOTRON_MODEL": "nvidia/nemotron-super-49b",
            },
        ):
            with patch("httpx.AsyncClient", return_value=client):
                provider = NebiusProvider()
                assert provider.model_name == "nvidia/nemotron-super-49b"
                await provider.complete([LLMMessage(role="user", content="q")])

        # Trailing slash on the base URL must not double up in the path.
        assert client.post.call_args[0][0] == "https://gateway.internal/v1/chat/completions"
        assert client.post.call_args[1]["json"]["model"] == "nvidia/nemotron-super-49b"

    async def test_complete_handles_missing_usage_and_empty_choices(self):
        client = _mock_client({"choices": []})
        with patch.dict(os.environ, {"NEBIUS_API_KEY": "k"}):
            with patch("httpx.AsyncClient", return_value=client):
                out = await NebiusProvider().complete([LLMMessage(role="user", content="q")])
        assert out.content == ""
        assert out.prompt_tokens == 0


class TestProviderFactory:
    def test_defaults_to_nebius_without_env(self):
        with patch.dict(os.environ, {}, clear=True):
            assert isinstance(get_provider(), NebiusProvider)

    def test_respects_model_provider_env(self):
        with patch.dict(os.environ, {"MODEL_PROVIDER": "Nebius"}):
            assert isinstance(get_provider(), NebiusProvider)

    def test_explicit_name_beats_env(self):
        with patch.dict(os.environ, {"MODEL_PROVIDER": "unknown"}):
            assert isinstance(get_provider("nebius"), NebiusProvider)

    def test_unknown_provider_raises_with_guidance(self):
        with pytest.raises(ValueError, match="nebius"):
            get_provider("openai-gpt-nope")

    def test_supported_providers_lists_nebius(self):
        assert "nebius" in supported_providers()

    def test_custom_provider_only_needs_three_members(self):
        assert issubclass(_StubProvider, LLMProvider)
