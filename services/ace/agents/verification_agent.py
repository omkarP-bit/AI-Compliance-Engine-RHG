"""Verification agent — interprets re-scan and compatibility results.

It may *propose* a retry, but it can never override a compatibility failure:
an ``INCOMPATIBLE`` verdict from the backend scanner is a hard stop that routes
to escalation. Agent confidence is not a licence to ignore application safety.
"""

from __future__ import annotations

import json
import re

from ace.agents.state import NextAction, Verdict
from ace.llm.base import LLMMessage
from ace.llm.provider import get_provider

SYSTEM_PROMPT = """You are a release verification engineer.
Given the result of an artifact mutation, OPA re-scan, and compatibility check,
determine whether the remediation succeeded and what to do next.
Return ONLY valid JSON."""

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

ESCALATE_FALLBACK = {
    "verdict": Verdict.FAIL,
    "next_action": NextAction.ESCALATE,
    "diagnosis": "Verification agent response could not be parsed",
    "retry_safe": False,
    "escalation_reason": "Agent parse failure — human review required",
}


class VerificationAgent:
    """Decides whether a remediation passed, should be retried, or must escalate."""

    name = "verification-agent"

    def __init__(self, provider_name: str = "nebius"):
        self.provider_name = provider_name
        self.llm = get_provider(provider_name)

    async def evaluate(
        self,
        finding: dict,
        remediation_plan: dict,
        rescan_findings: list[dict],
        compatibility_result: dict,
        retry_count: int,
        max_retries: int,
    ) -> dict:
        """Interpret mutation + re-scan + compatibility outcomes.

        Never raises: an unusable response escalates to human review.
        """
        messages = [
            LLMMessage(role="system", content=SYSTEM_PROMPT),
            LLMMessage(
                role="user",
                content=self._build_prompt(
                    finding,
                    remediation_plan,
                    rescan_findings,
                    compatibility_result,
                    retry_count,
                    max_retries,
                ),
            ),
        ]
        try:
            resp = await self.llm.complete(messages, max_tokens=512, temperature=0.1)
        except Exception as exc:  # noqa: BLE001 - reasoning must never break the gate
            return {**ESCALATE_FALLBACK, "diagnosis": f"LLM unavailable: {exc}"}
        return self._parse(resp.content)

    def _build_prompt(
        self,
        finding: dict,
        plan: dict,
        rescan_findings: list[dict],
        compat: dict,
        retry_count: int,
        max_retries: int,
    ) -> str:
        rule_id = finding.get("rule_id")
        same_rule = [f for f in (rescan_findings or []) if f.get("rule_id") == rule_id]
        remaining = max(max_retries - retry_count, 0)
        return f"""Original finding:
{rule_id} — {finding.get('message')}

Remediation applied:
{json.dumps(plan.get('proposed_patches', []), indent=2, default=str)}

OPA re-scan result:
Remaining findings for this rule: {len(same_rule)}
All findings cleared: {not rescan_findings}

Compatibility result:
Verdict:    {compat.get('verdict', 'SKIPPED')}
Mismatches: {json.dumps(compat.get('mismatches', []), indent=2, default=str)}

Retry context:
Attempt: {retry_count + 1} of {max_retries}
Remaining retries: {remaining}

Determine next action. Return JSON:
{{
  "verdict":           "PASS" | "FAIL" | "INCOMPATIBLE",
  "next_action":       "GATE" | "RETRY" | "ESCALATE",
  "diagnosis":         "what went wrong or why it passed",
  "retry_safe":        true | false,
  "escalation_reason": "only if next_action is ESCALATE"
}}"""

    def _parse(self, content: str) -> dict:
        match = _JSON_OBJECT_RE.search(content or "")
        if not match:
            return dict(ESCALATE_FALLBACK)
        try:
            parsed = json.loads(match.group())
        except json.JSONDecodeError:
            return dict(ESCALATE_FALLBACK)
        if not isinstance(parsed, dict):
            return dict(ESCALATE_FALLBACK)

        verdict = str(parsed.get("verdict") or Verdict.FAIL).upper()
        if verdict not in (Verdict.PASS, Verdict.FAIL, Verdict.INCOMPATIBLE):
            verdict = Verdict.FAIL

        next_action = str(parsed.get("next_action") or NextAction.ESCALATE).upper()
        if next_action not in (NextAction.GATE, NextAction.RETRY, NextAction.ESCALATE):
            next_action = NextAction.ESCALATE

        # Hard safety invariant: an INCOMPATIBLE compatibility result is never
        # downgraded to GATE or RETRY, whatever the model asked for.
        if verdict == Verdict.INCOMPATIBLE and next_action != NextAction.ESCALATE:
            next_action = NextAction.ESCALATE
            parsed["escalation_reason"] = (
                parsed.get("escalation_reason")
                or "Compatibility check failed — agent cannot override an INCOMPATIBLE verdict"
            )

        result = {
            "verdict": verdict,
            "next_action": next_action,
            "diagnosis": parsed.get("diagnosis", ""),
            "retry_safe": bool(parsed.get("retry_safe", False)),
            "escalation_reason": parsed.get("escalation_reason", ""),
        }
        if next_action == NextAction.ESCALATE and not result["escalation_reason"]:
            result["escalation_reason"] = "Verification escalated to human review"
        return result
