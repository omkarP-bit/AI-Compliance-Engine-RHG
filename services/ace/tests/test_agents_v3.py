import os
from unittest.mock import AsyncMock, patch

import pytest

from ace.agents.context_agent import ContextAgent
from ace.agents.remediation_agent import RemediationAgent
from ace.agents.state import (
    GateDecision,
    NextAction,
    RemediationAction,
    Verdict,
    initial_state,
    severity_rank,
    should_block,
    state_summary,
)
from ace.agents.verification_agent import VerificationAgent
from ace.llm.base import LLMResponse

FINDING = {
    "rule_id": "CIS-K8S-5.2.1",
    "severity": "HIGH",
    "message": "Privileged container",
    "artifact": "deploy.yaml",
    "resource": "Deployment/api",
}


def _agent(cls, content):
    agent = cls()
    agent.llm = AsyncMock()
    agent.llm.complete = AsyncMock(
        return_value=LLMResponse(content=content, model="test", provider="test")
    )
    return agent


def _boom_agent(cls):
    agent = cls()
    agent.llm = AsyncMock()
    agent.llm.complete = AsyncMock(side_effect=RuntimeError("provider down"))
    return agent


def _state():
    return initial_state(
        pipeline_id="p1",
        artifacts=[{"type": "kubernetes", "name": "deploy.yaml", "content": ""}],
        backend_scan={"language": "python", "port_bindings": [8000]},
    )


@pytest.mark.asyncio
class TestContextAgent:
    async def test_parses_json_response(self):
        agent = _agent(
            ContextAgent,
            '{"what_is_deployed": "prod API", "why_violation_matters": "host escape",'
            ' "affected_components": ["api"], "context_risk_note": "multi-tenant"}',
        )
        out = await agent.analyze(_state(), FINDING)
        assert out["what_is_deployed"] == "prod API"
        assert out["why_violation_matters"] == "host escape"
        assert out["affected_components"] == ["api"]

    async def test_extracts_json_from_fenced_or_chatty_response(self):
        agent = _agent(
            ContextAgent,
            'Sure! Here you go:\n```json\n{"why_violation_matters": "privilege escalation",'
            ' "affected_components": []}\n```\nHope that helps.',
        )
        out = await agent.analyze(_state(), FINDING)
        assert out["why_violation_matters"] == "privilege escalation"

    async def test_malformed_json_degrades_to_fallback(self):
        agent = _agent(ContextAgent, "{not valid json,,,}")
        out = await agent.analyze(_state(), FINDING)
        assert out["why_violation_matters"] == FINDING["message"]
        assert "malformed" in out["context_risk_note"]

    async def test_no_json_at_all_degrades_to_fallback(self):
        agent = _agent(ContextAgent, "I am unable to help with that request.")
        out = await agent.analyze(_state(), FINDING)
        assert "no JSON object" in out["context_risk_note"]

    async def test_provider_failure_never_raises(self):
        agent = _boom_agent(ContextAgent)
        out = await agent.analyze(_state(), FINDING)
        assert "provider down" in out["context_risk_note"]

    async def test_prompt_never_asks_agent_for_policy(self):
        agent = _agent(ContextAgent, "{}")
        await agent.analyze(_state(), FINDING)
        sent = agent.llm.complete.call_args[0][0]
        assert "OPA" in sent[0].content
        assert "NOT invent new security policy" in sent[0].content
        assert FINDING["rule_id"] in sent[1].content


@pytest.mark.asyncio
class TestRemediationAgent:
    async def test_parses_patch_plan(self):
        agent = _agent(
            RemediationAgent,
            '{"action": "PATCH", "reason": "safe: no host access needed", "confidence": 0.93,'
            ' "requires_human_review": false,'
            ' "proposed_patches": [{"op": "replace",'
            ' "path": "/spec/containers/0/securityContext/privileged", "value": false}],'
            ' "safety_notes": "requires restart"}',
        )
        out = await agent.plan(FINDING, {}, {"language": "python"}, retry_count=0)
        assert out["action"] == RemediationAction.PATCH
        assert out["confidence"] == 0.93
        assert out["requires_human_review"] is False
        assert out["proposed_patches"][0]["path"].endswith("/privileged")

    async def test_patch_without_patches_is_downgraded_to_escalate(self):
        agent = _agent(
            RemediationAgent,
            '{"action": "PATCH", "reason": "trust me", "confidence": 0.99,'
            ' "requires_human_review": false, "proposed_patches": []}',
        )
        out = await agent.plan(FINDING, {}, {}, retry_count=0)
        # A no-op patch that reports success would let the gate claim a fix.
        assert out["action"] == RemediationAction.ESCALATE
        assert out["requires_human_review"] is True

    async def test_unknown_action_falls_back_to_escalate(self):
        agent = _agent(
            RemediationAgent,
            '{"action": "DELETE_PRODUCTION", "confidence": 1.0, "requires_human_review": false,'
            ' "proposed_patches": [{"op": "add", "path": "/x", "value": 1}]}',
        )
        assert (await agent.plan(FINDING, {}, {}, retry_count=0))["action"] == RemediationAction.ESCALATE

    async def test_lowercase_action_is_accepted(self):
        agent = _agent(
            RemediationAgent,
            '{"action": "skip", "reason": "informational", "confidence": 0.9,'
            ' "requires_human_review": false, "proposed_patches": []}',
        )
        assert (await agent.plan(FINDING, {}, {}, retry_count=0))["action"] == RemediationAction.SKIP

    async def test_non_numeric_confidence_coerced(self):
        agent = _agent(
            RemediationAgent,
            '{"action": "SKIP", "confidence": "very high", "requires_human_review": false,'
            ' "proposed_patches": []}',
        )
        assert (await agent.plan(FINDING, {}, {}, retry_count=0))["confidence"] == 0.5

    async def test_malformed_response_escalates(self):
        agent = _agent(RemediationAgent, "<<garbage>>")
        out = await agent.plan(FINDING, {}, {}, retry_count=0)
        assert out["action"] == RemediationAction.ESCALATE
        assert out["confidence"] == 0.0
        assert out["requires_human_review"] is True

    async def test_provider_failure_escalates_rather_than_raising(self):
        out = await _boom_agent(RemediationAgent).plan(FINDING, {}, {}, retry_count=0)
        assert out["action"] == RemediationAction.ESCALATE
        assert "provider down" in out["reason"]

    async def test_retry_count_is_surfaced_to_the_model(self):
        agent = _agent(RemediationAgent, '{"action": "ESCALATE"}')
        await agent.plan(FINDING, {}, {}, retry_count=2)
        prompt = agent.llm.complete.call_args[0][0][1].content
        assert "Previous attempt #2 failed" in prompt

    async def test_prompt_excludes_agents_own_oversight(self):
        agent = _agent(RemediationAgent, '{"action": "ESCALATE"}')
        await agent.plan(FINDING, {}, {}, retry_count=0)
        assert "You do NOT apply the mutation" in agent.llm.complete.call_args[0][0][0].content


@pytest.mark.asyncio
class TestVerificationAgent:
    def _evaluate(self, content, **overrides):
        agent = _agent(VerificationAgent, content)
        kwargs = {
            "finding": FINDING,
            "remediation_plan": {"proposed_patches": []},
            "rescan_findings": [],
            "compatibility_result": {"verdict": "COMPATIBLE", "mismatches": []},
            "retry_count": 0,
            "max_retries": 3,
        }
        kwargs.update(overrides)
        return agent, kwargs

    async def test_clean_rescan_passes_to_gate(self):
        agent, kwargs = self._evaluate(
            '{"verdict": "PASS", "next_action": "GATE", "diagnosis": "privilege removed",'
            ' "retry_safe": false}'
        )
        out = await agent.evaluate(**kwargs)
        assert out["verdict"] == Verdict.PASS
        assert out["next_action"] == NextAction.GATE
        assert out["diagnosis"] == "privilege removed"

    async def test_retry_request_is_honoured(self):
        agent, kwargs = self._evaluate(
            '{"verdict": "FAIL", "next_action": "RETRY", "diagnosis": "patch was a no-op",'
            ' "retry_safe": true}',
            retry_count=1,
        )
        out = await agent.evaluate(**kwargs)
        assert out["next_action"] == NextAction.RETRY
        assert out["retry_safe"] is True

    async def test_incompatible_cannot_be_downgraded_to_gate(self):
        agent, kwargs = self._evaluate(
            '{"verdict": "INCOMPATIBLE", "next_action": "GATE", "retry_safe": true,'
            ' "diagnosis": "app binds 0.0.0.0 but we set 127.0.0.1"}',
            compatibility_result={"verdict": "INCOMPATIBLE", "mismatches": [{"severity": "HIGH"}]},
        )
        out = await agent.evaluate(**kwargs)
        # The model asked to proceed; a broken backend is a hard stop regardless.
        assert out["verdict"] == Verdict.INCOMPATIBLE
        assert out["next_action"] == NextAction.ESCALATE
        assert "cannot override" in out["escalation_reason"]

    async def test_incompatible_cannot_be_downgraded_to_retry(self):
        agent, kwargs = self._evaluate(
            '{"verdict": "INCOMPATIBLE", "next_action": "RETRY", "retry_safe": true}',
            compatibility_result={"verdict": "INCOMPATIBLE", "mismatches": []},
        )
        assert (await agent.evaluate(**kwargs))["next_action"] == NextAction.ESCALATE

    async def test_unknown_verdict_and_action_fail_closed(self):
        agent, kwargs = self._evaluate('{"verdict": "PROBABLY_FINE", "next_action": "SHIP_IT"}')
        out = await agent.evaluate(**kwargs)
        assert out["verdict"] == Verdict.FAIL
        assert out["next_action"] == NextAction.ESCALATE

    async def test_escalation_always_carries_a_reason(self):
        agent, kwargs = self._evaluate('{"verdict": "FAIL", "next_action": "ESCALATE"}')
        assert (await agent.evaluate(**kwargs))["escalation_reason"]

    async def test_malformed_response_escalates(self):
        agent, kwargs = self._evaluate("totally unparseable")
        out = await agent.evaluate(**kwargs)
        assert out["verdict"] == Verdict.FAIL
        assert out["next_action"] == NextAction.ESCALATE
        assert out["retry_safe"] is False

    async def test_provider_failure_escalates_rather_than_raising(self):
        agent = _boom_agent(VerificationAgent)
        out = await agent.evaluate(FINDING, {}, [], {"verdict": "COMPATIBLE"}, 0, 3)
        assert out["next_action"] == NextAction.ESCALATE
        assert "provider down" in out["diagnosis"]


class TestStateContract:
    def test_initial_state_seeds_every_accumulator(self):
        state = initial_state("p1")
        for key in ("audit_trail", "resolved_findings", "blocked_findings", "patched_artifacts"):
            assert state[key] == []
        assert state["current_state"] == "RECEIVED"
        assert state["decision"] == GateDecision.PENDING
        assert state["escalated"] is False

    def test_tuning_defaults_come_from_the_environment(self):
        with patch.dict(
            os.environ,
            {
                "AGENT_MAX_RETRIES": "5",
                "AGENT_CONFIDENCE_THRESHOLD": "0.5",
                "BLOCK_ON_SEVERITY": "CRITICAL",
            },
        ):
            state = initial_state("p1")
        assert (state["max_retries"], state["confidence_threshold"]) == (5, 0.5)
        assert state["block_on_severity"] == "CRITICAL"

    def test_explicit_arguments_beat_the_environment(self):
        with patch.dict(os.environ, {"AGENT_MAX_RETRIES": "5", "AGENT_CONFIDENCE_THRESHOLD": "0.5"}):
            state = initial_state("p1", max_retries=1, confidence_threshold=0.99, block_on_severity="LOW")
        assert (state["max_retries"], state["confidence_threshold"]) == (1, 0.99)
        assert state["block_on_severity"] == "LOW"

    def test_unparseable_environment_values_fall_back_to_defaults(self):
        with patch.dict(os.environ, {"AGENT_MAX_RETRIES": "lots", "AGENT_CONFIDENCE_THRESHOLD": "high"}):
            state = initial_state("p1")
        assert state["max_retries"] == 3
        assert state["confidence_threshold"] == 0.85

    def test_initial_state_does_not_share_mutable_defaults(self):
        a, b = initial_state("p1"), initial_state("p2")
        a["findings"].append({"rule_id": "X"})
        a["artifacts"].append({"name": "x"})
        assert b["findings"] == []
        assert b["artifacts"] == []

    def test_initial_state_mirrors_findings_into_pending_queue(self):
        state = initial_state("p1", findings=[FINDING])
        assert state["pending"] == [FINDING]
        state["pending"].append({"rule_id": "Y"})
        assert len(state["findings"]) == 1

    def test_severity_ranking_and_blocking(self):
        assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("LOW")
        assert severity_rank("nonsense") == 0
        assert should_block("HIGH", "HIGH") is True
        assert should_block("MEDIUM", "HIGH") is False
        assert should_block("CRITICAL", "CRITICAL") is True

    def test_state_summary_is_log_safe_and_total(self):
        summary = state_summary({"current_state": "MUTATING", "finding": FINDING, "pending": []})
        assert "MUTATING" in summary
        assert "CIS-K8S-5.2.1" in summary
        assert state_summary({}).startswith("state=")
