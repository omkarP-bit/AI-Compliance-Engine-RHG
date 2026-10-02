"""Agentic release-hardening layer (Phase 12).

The agents here reason; they never decide. OPA is the sole policy authority,
``PatchEngine`` is the only thing that mutates, and an ``INCOMPATIBLE``
compatibility result cannot be overridden by a model.
"""

from ace.agents.context_agent import ContextAgent
from ace.agents.graph import build_release_graph, recursion_config, run_release_loop
from ace.agents.remediation_agent import RemediationAgent
from ace.agents.state import (
    AgentState,
    GateDecision,
    NextAction,
    RemediationAction,
    Verdict,
    initial_state,
    should_block,
    state_summary,
)
from ace.agents.verification_agent import VerificationAgent

__all__ = [
    "AgentState",
    "ContextAgent",
    "GateDecision",
    "NextAction",
    "RemediationAction",
    "RemediationAgent",
    "VerificationAgent",
    "Verdict",
    "build_release_graph",
    "initial_state",
    "recursion_config",
    "run_release_loop",
    "should_block",
    "state_summary",
]
