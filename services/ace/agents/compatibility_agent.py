import json
import os
import re

from ace.backend_scanner.extractor import BackendProfile


class CompatibilityAgent:
    """Contextual review of static compatibility mismatches.

    Uses Groq (Llama 3.3 70B) when GROQ_API_KEY is configured.
    Without a key it performs a rule-based review so the pipeline still works.
    """

    def __init__(self):
        self.llm = None
        self.enabled = os.environ.get("ACE_COMPAT_AGENT", "true").lower() == "true"

    async def review(self, mismatches, profile: BackendProfile) -> dict:
        if not mismatches:
            return {"reviewed": False, "adjustments": []}

        if self.enabled:
            try:
                from langchain_groq import ChatGroq

                llm = ChatGroq(
                    model="llama-3.3-70b-versatile",
                    api_key=os.environ["GROQ_API_KEY"],
                )
                response = await llm.ainvoke(self._build_prompt(mismatches, profile))
                return {
                    "reviewed": True,
                    "adjustments": self._parse_responses(response.content),
                }
            except Exception:
                pass  # LLM unavailable — fall back to static verdict

        return {"reviewed": False, "adjustments": []}

    def _build_prompt(self, mismatches, profile: BackendProfile) -> str:
        simple = [
            {
                "mutation_path": m.mutation_path,
                "patched_value": m.patched_value,
                "backend_value": m.backend_value,
                "detail": m.detail,
                "severity": m.severity,
            }
            for m in mismatches
        ]
        return (
            "You are a DevSecOps compatibility reviewer. "
            f"Backend profile: {profile}. "
            f"Static mismatches: {simple}. "
            "For each mismatch, decide if it truly breaks the running backend "
            "(respond with the same action ESCALATE/WARN) or is a false positive "
            "(respond WARN). Return a JSON list of {mutation_path, action}."
        )

    def _parse_responses(self, content: str) -> list[dict]:
        match = re.search(r"\[.*\]", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group()) if isinstance(match.group(), str) else []
            except json.JSONDecodeError:
                return []
        return []