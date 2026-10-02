"""Remediation agent — proposes a remediation plan for a single finding.

Proposes only. Applying the mutation is :class:`~ace.mutator.patch_engine.PatchEngine`'s
job, and no patch leaves this module.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ace.agents.state import RemediationAction
from ace.llm.base import LLMMessage
from ace.llm.provider import get_provider

SYSTEM_PROMPT = """You are a DevSecOps remediation engineer.
Given a compliance finding and its context, propose a safe remediation strategy.
You do NOT apply the mutation — you propose it. PatchEngine applies it.
Return ONLY valid JSON — no markdown, no explanation outside the JSON."""

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

_ESCALATE_FALLBACK = {
    "action": RemediationAction.ESCALATE,
    "reason": "Agent response could not be parsed — escalating to human review",
    "confidence": 0.0,
    "requires_human_review": True,
    "proposed_patches": [],
    "safety_notes": "No plan produced; a human must remediate this finding.",
}


class RemediationAgent:
    """Plans a contextually safe remediation for one finding."""

    name = "remediation-agent"

    def __init__(self, provider_name: str = "nebius"):
        self.provider_name = provider_name
        self.llm = get_provider(provider_name)

    async def plan(
        self,
        finding: dict,
        context: dict,
        backend_scan: dict,
        retry_count: int = 0,
    ) -> dict:
        """Return a structured remediation plan for ``finding``.

        Never raises: a failed or unparseable response escalates rather than
        silently proposing a half-formed patch.
        """
        messages = [
            LLMMessage(role="system", content=SYSTEM_PROMPT),
            LLMMessage(role="user", content=self._build_prompt(finding, context, backend_scan, retry_count)),
        ]
        try:
            resp = await self.llm.complete(messages, max_tokens=768, temperature=0.15)
        except Exception as exc:  # noqa: BLE001 - reasoning must never break the gate
            return {**_ESCALATE_FALLBACK, "reason": f"LLM unavailable: {exc}"}
        return self._parse(resp.content)

    def _build_prompt(
        self,
        finding: dict,
        context: dict,
        backend_scan: dict,
        retry_count: int,
    ) -> str:
        retry_note = (
            f"\nPrevious attempt #{retry_count} failed. Propose a different safe remediation."
            if retry_count > 0
            else ""
        )
        return f"""OPA finding:
Rule:     {finding.get('rule_id')}
Severity: {finding.get('severity')}
Message:  {finding.get('message')}
Artifact: {finding.get('artifact')}

Context (from Context Agent):
{json.dumps(context or {}, indent=2, default=str)}

Backend profile:
Language:     {backend_scan.get('language')}
Port bindings:{backend_scan.get('port_bindings', [])}
Env vars:     {backend_scan.get('env_vars_used', [])}
Routes:       {backend_scan.get('routes', [])}
{retry_note}

Propose a remediation. Return JSON:
{{
  "action":               "PATCH" | "SKIP" | "ESCALATE",
  "reason":               "why this remediation is safe in this context",
  "confidence":           0.0-1.0,
  "requires_human_review": true | false,
  "proposed_patches":     [
    {{"op": "replace|add|remove", "path": "/json/patch/path", "value": <value>}}
  ],
  "safety_notes":         "any caveats the verification agent should check"
}}"""

    def _parse(self, content: str) -> dict:
        match = _JSON_OBJECT_RE.search(content or "")
        if not match:
            return dict(_ESCALATE_FALLBACK)
        try:
            parsed = json.loads(match.group())
        except json.JSONDecodeError:
            return dict(_ESCALATE_FALLBACK)
        if not isinstance(parsed, dict):
            return dict(_ESCALATE_FALLBACK)

        action = str(parsed.get("action") or RemediationAction.ESCALATE).upper()
        if action not in (
            RemediationAction.PATCH,
            RemediationAction.SKIP,
            RemediationAction.ESCALATE,
        ):
            action = RemediationAction.ESCALATE

        patches = [p for p in (parsed.get("proposed_patches") or []) if isinstance(p, dict)]
        if action == RemediationAction.PATCH and not patches:
            # A PATCH with nothing to apply is not actionable — treat as escalate
            # rather than committing a no-op and reporting success.
            action = RemediationAction.ESCALATE
            parsed["requires_human_review"] = True

        return {
            "action": action,
            "reason": parsed.get("reason", ""),
            "confidence": _coerce_float(parsed.get("confidence"), 0.5),
            "requires_human_review": bool(parsed.get("requires_human_review", True)),
            "proposed_patches": patches,
            "safety_notes": parsed.get("safety_notes", ""),
        }


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
