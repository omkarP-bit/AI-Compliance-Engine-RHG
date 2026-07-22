import json
import os
import re

from langchain_groq import ChatGroq

from ace.agents.base_agent import BaseAgent, AgentResult


class ArtifactAgent(BaseAgent):
    name = "artifact_agent"

    def __init__(self):
        self.llm = ChatGroq(
            model="llama-3.3-70b-versatile",
            api_key=os.environ.get("GROQ_API_KEY", "placeholder"),
        )

    async def run(self, artifact: dict, findings: list[dict], context: dict) -> AgentResult:
        if not findings:
            return AgentResult(self.name, 1.0, [], [], False, {})

        prompt = self._build_prompt(artifact, findings)
        response = await self.llm.ainvoke(prompt)
        analysis = self._parse_response(response.content)

        return AgentResult(
            agent_name=self.name,
            confidence=analysis.get("confidence", 0.8),
            enriched_findings=analysis.get("enriched_findings", findings),
            recommendations=analysis.get("recommendations", []),
            escalate=analysis.get("escalate", False),
            context={"raw_analysis": response.content},
        )

    def _build_prompt(self, artifact: dict, findings: list[dict]) -> str:
        return f"""You are a Kubernetes security expert reviewing deployment artifact violations.

Artifact summary:
{artifact.get("metadata", {})}

OPA findings:
{findings}

Analyze the security context of these findings. For each finding:
1. Assess actual exploitability in this specific context
2. Note if image digest or base image affects severity
3. Identify if findings are related or form a compound risk
4. Suggest a precise fix

Return JSON:
{{
  "confidence": 0.0-1.0,
  "enriched_findings": [...],
  "recommendations": ["..."],
  "escalate": true/false
}}"""

    def _parse_response(self, content: str) -> dict:
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {"confidence": 0.5, "enriched_findings": [], "recommendations": [], "escalate": True}
