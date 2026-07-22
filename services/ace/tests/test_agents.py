import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from ace.agents.artifact_agent import ArtifactAgent
from ace.agents.base_agent import AgentResult


SAMPLE_FINDINGS = [
    {"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH", "message": "Privileged container", "patchable": True}
]

SAMPLE_ARTIFACT = {
    "metadata": {"kind": "Deployment", "namespace": "production", "containers": [{"name": "app"}]}
}


@pytest.mark.asyncio
class TestArtifactAgent:
    async def test_returns_empty_result_when_no_findings(self):
        agent = ArtifactAgent()
        result = await agent.run(SAMPLE_ARTIFACT, [], {})
        assert isinstance(result, AgentResult)
        assert result.enriched_findings == []
        assert result.escalate is False

    async def test_calls_llm_when_findings_present(self):
        mock_response = MagicMock()
        mock_response.content = '{"confidence": 0.9, "enriched_findings": [], "recommendations": ["Fix privileged"], "escalate": false}'

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)

        with patch("ace.agents.artifact_agent.ChatGroq", return_value=mock_llm):
            agent = ArtifactAgent()
            result = await agent.run(SAMPLE_ARTIFACT, SAMPLE_FINDINGS, {})
            assert result.confidence == 0.9
            assert len(result.recommendations) == 1

    async def test_escalates_on_low_confidence(self):
        mock_response = MagicMock()
        mock_response.content = '{"confidence": 0.3, "enriched_findings": [], "recommendations": [], "escalate": true}'

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)

        with patch("ace.agents.artifact_agent.ChatGroq", return_value=mock_llm):
            agent = ArtifactAgent()
            result = await agent.run(SAMPLE_ARTIFACT, SAMPLE_FINDINGS, {})
            assert result.escalate is True

    async def test_handles_malformed_llm_response(self):
        mock_response = MagicMock()
        mock_response.content = "I cannot assess this artifact."

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)

        with patch("ace.agents.artifact_agent.ChatGroq", return_value=mock_llm):
            agent = ArtifactAgent()
            result = await agent.run(SAMPLE_ARTIFACT, SAMPLE_FINDINGS, {})
            assert isinstance(result, AgentResult)
            assert result.escalate is True
