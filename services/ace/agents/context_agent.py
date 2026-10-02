"""Context agent — explains what is being deployed and why a finding matters.

Deliberately constrained: this agent explains, it does not decide. OPA remains
the sole policy authority and the verification agent owns every routing call.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ace.llm.base import LLMMessage
from ace.llm.provider import get_provider

SYSTEM_PROMPT = """You are a senior DevSecOps engineer reviewing a CI/CD compliance finding.
Your role is to understand the release context and explain the finding clearly.
You must NOT invent new security policy. OPA is the policy authority.
Return ONLY valid JSON — no markdown, no preamble."""

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


class ContextAgent:
    """Understands the release context around a single finding."""

    name = "context-agent"

    def __init__(self, provider_name: str = "nebius"):
        self.provider_name = provider_name
        self.llm = get_provider(provider_name)

    async def analyze(self, state: dict[str, Any], finding: dict) -> dict:
        """Return a context summary for one finding.

        Never raises: an unparseable or failed model response degrades to a
        static fallback so the release loop keeps its deterministic path.
        """
        messages = [
            LLMMessage(role="system", content=SYSTEM_PROMPT),
            LLMMessage(role="user", content=self._build_prompt(state, finding)),
        ]
        try:
            resp = await self.llm.complete(messages, max_tokens=512, temperature=0.1)
        except Exception as exc:  # noqa: BLE001 - reasoning must never break the gate
            return self._fallback(finding, reason=f"LLM unavailable: {exc}")
        return self._parse(resp.content, finding)

    def _build_prompt(self, state: dict[str, Any], finding: dict) -> str:
        backend = state.get("backend_scan") or {}
        return f"""Release context:
Environment: {state.get('environment', 'production')}
Backend: {backend.get('language', 'unknown')} / {backend.get('frameworks', [])}
Port bindings: {backend.get('port_bindings', [])}
Env vars used: {backend.get('env_vars_used', [])}

OPA finding:
Rule:     {finding.get('rule_id')}
Severity: {finding.get('severity')}
Artifact: {finding.get('artifact')}
Message:  {finding.get('message')}

Answer these questions in JSON:
{{
  "what_is_deployed":    "one sentence",
  "why_violation_matters": "one sentence — in this specific context",
  "affected_components": ["list of components that could be impacted"],
  "context_risk_note":   "any additional context that affects remediation"
}}"""

    def _parse(self, content: str, finding: dict) -> dict:
        match = _JSON_OBJECT_RE.search(content or "")
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                return self._fallback(finding, reason="context agent returned malformed JSON")
            if isinstance(parsed, dict):
                return {
                    "what_is_deployed": parsed.get("what_is_deployed", ""),
                    "why_violation_matters": parsed.get("why_violation_matters", ""),
                    "affected_components": parsed.get("affected_components") or [],
                    "context_risk_note": parsed.get("context_risk_note", ""),
                }
        return self._fallback(finding, reason="context agent returned no JSON object")

    @staticmethod
    def _fallback(finding: dict, reason: str) -> dict:
        return {
            "what_is_deployed": "Unknown — context agent could not analyse this finding",
            "why_violation_matters": finding.get("message", ""),
            "affected_components": [],
            "context_risk_note": reason,
        }
