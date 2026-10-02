"""LangGraph state machine for the agentic release-hardening loop.

    analyzing -> reasoning -> plan_remediation -> mutating
              -> compatibility_check -> verification -> (retry | next_finding)
              -> gate

Divergences from the design in DEVELOPMENT.md §12.5, all deliberate:

* **State shape.** ``AgentState`` is a ``TypedDict``; see ``state.py`` for why a
  dataclass does not survive ``ainvoke``.
* **Multi-finding.** The sketch only ever read ``state.findings[0]``, silently
  discarding every later violation. This graph drains a ``pending`` queue, so a
  manifest with three violations gets three remediation cycles.
* **Artifact round-tripping.** The sketch hardcoded ``yaml.safe_load``/
  ``yaml.dump``; that corrupts Terraform plan JSON, Dockerfiles and workflows.
  Encoding is delegated to ``ace.engine.artifact_codec``.
* **PatchEngine location.** The sketch reached for ``..mutator.patch_engine``,
  which only existed under RHG. The engine now lives in ``ace.mutator`` and RHG
  re-exports it.
* **Compatibility check.** The sketch imported ``run_compatibility_check``,
  which did not exist. It does now, and is called in-process.
* **Retry routing.** Routing is driven by an explicit ``agent_next_action``
  field rather than by overloading ``current_state``.

The compatibility gate is not overridable here: an ``INCOMPATIBLE`` result
routes to escalation regardless of what the verification agent proposes.
"""

from __future__ import annotations

import os
import time
from typing import Any

from langgraph.graph import END, StateGraph

from ace.agents.context_agent import ContextAgent
from ace.agents.remediation_agent import RemediationAgent
from ace.agents.state import (
    AgentState,
    GateDecision,
    NextAction,
    RemediationAction,
    S,
    Verdict,
    should_block,
)
from ace.agents.verification_agent import VerificationAgent
from ace.api.compatibility import run_compatibility_check
from ace.api.websocket import publish_event
from ace.engine.artifact_codec import (
    ArtifactDecodeError,
    artifact_type_of,
    decode_artifact,
    encode_content,
    find_artifact,
    policy_path_for,
)
from ace.engine.opa_client import OPAClient
from ace.metrics.prometheus import AGENT_DURATION
from ace.mutator.patch_engine import PatchEngine

AGENT_EVENT_CHANNEL = "agentic"

#: Node name -> the agent that runs in it, for metrics and event payloads.
_AGENT_FOR_NODE = {
    "reasoning": "context-agent",
    "plan_remediation": "remediation-agent",
    "verification": "verification-agent",
}


def build_release_graph(
    provider: str = "nebius",
    agents: dict[str, Any] | None = None,
    opa_client: OPAClient | None = None,
    patch_engine: type[PatchEngine] | None = None,
    checkpointer: Any = None,
):
    """Compile the release-hardening graph.

    Args:
        provider: LLM provider name passed to each agent.
        agents: Pre-built agent overrides keyed by node name
            (``reasoning``, ``plan_remediation``, ``verification``). Used by
            tests and by callers that want a policy-backed planner.
        opa_client: OPA client override. Defaults to an env-configured client.
        patch_engine: Patch engine override. Defaults to the canonical engine.
        checkpointer: Optional LangGraph checkpointer for durable runs.
    """
    overrides = agents or {}
    ctx_agent = overrides.get("reasoning") or ContextAgent(provider)
    rem_agent = overrides.get("plan_remediation") or RemediationAgent(provider)
    verif_agent = overrides.get("verification") or VerificationAgent(provider)
    opa = opa_client or OPAClient(opa_url=os.environ.get("OPA_URL", "http://localhost:8181"))
    patcher = patch_engine or PatchEngine

    graph = StateGraph(AgentState)

    async def analyzing(state: AgentState) -> dict:
        return await _with_agent_timing("analyzing", _analyzing, state)

    async def reasoning(state: AgentState) -> dict:
        return await _with_agent_timing("reasoning", _reasoning, state, ctx_agent)

    async def plan_remediation(state: AgentState) -> dict:
        return await _with_agent_timing("plan_remediation", _plan_remediation, state, rem_agent)

    async def mutating(state: AgentState) -> dict:
        return await _with_agent_timing("mutating", _mutating, state, patcher)

    async def compatibility_check(state: AgentState) -> dict:
        return await _with_agent_timing("compatibility_check", _compatibility_check, state)

    async def verification(state: AgentState) -> dict:
        return await _with_agent_timing(
            "verification", _verification, state, verif_agent, opa, state.get("finding") or {}
        )

    async def next_finding(state: AgentState) -> dict:
        return _next_finding(state)

    async def gate(state: AgentState) -> dict:
        return _gate(state)

    for name, fn in (
        ("analyzing", analyzing),
        ("reasoning", reasoning),
        ("plan_remediation", plan_remediation),
        ("mutating", mutating),
        ("compatibility_check", compatibility_check),
        ("verification", verification),
        ("next_finding", next_finding),
        ("gate", gate),
    ):
        graph.add_node(name, fn)

    graph.set_entry_point("analyzing")

    graph.add_conditional_edges(
        "analyzing",
        lambda s: GateDecision.ALLOW if not s.get("findings") else "reasoning",
        {"reasoning": "reasoning", GateDecision.ALLOW: "gate"},
    )
    graph.add_edge("reasoning", "plan_remediation")
    graph.add_conditional_edges(
        "plan_remediation",
        _route_after_plan,
        {
            GateDecision.BLOCK: "gate",
            NextAction.NEXT_FINDING: "next_finding",
            "mutating": "mutating",
        },
    )
    graph.add_edge("mutating", "compatibility_check")
    graph.add_edge("compatibility_check", "verification")
    graph.add_conditional_edges(
        "verification",
        _route_after_verification,
        {
            GateDecision.BLOCK: "gate",
            "plan_remediation": "plan_remediation",
            "next_finding": "next_finding",
        },
    )
    graph.add_conditional_edges(
        "next_finding",
        lambda s: GateDecision.BLOCK if not s.get("pending") else "reasoning",
        {"reasoning": "reasoning", GateDecision.BLOCK: "gate"},
    )
    graph.add_edge("gate", END)

    return graph.compile(checkpointer=checkpointer)


def recursion_config(state: dict[str, Any], per_node: int = 2, headroom: int = 10) -> dict:
    """Recursion limit large enough for the worst case this graph can reach.

    LangGraph's default of 25 super-steps overflows easily: each finding costs
    five nodes, and every retry costs four more. Callers running
    ``ainvoke`` must pass this as ``config`` or the run dies with
    ``GraphRecursionError`` part-way through — after mutations have already been
    applied to the workspace.
    """
    findings = max(len(state.get("findings") or state.get("pending") or []), 1)
    retries = int(state.get("max_retries") or 0)
    return {"recursion_limit": findings * (per_node * (1 + retries) + 1) + headroom}


async def run_release_loop(graph, state: AgentState) -> dict:
    """Run the compiled graph with a recursion limit sized for ``state``."""
    return await graph.ainvoke(state, config=recursion_config(state))


# ---------------------------------------------------------------------------
# nodes
# ---------------------------------------------------------------------------


async def _analyzing(state: AgentState) -> dict:
    findings = list(state.get("findings") or [])
    if not findings:
        await _emit("agent.reasoning.completed", state, {"skipped": "no findings"})
        return {
            "current_state": S.GATE,
            "decision": GateDecision.ALLOW,
            "audit_trail": [
                {
                    "step": "analyzing",
                    "state": S.ANALYZING,
                    "finding_count": 0,
                    "outcome": "no findings — fast path to gate",
                }
            ],
        }

    return {
        "current_state": S.FINDINGS_FOUND,
        "pending": findings,
        "finding": findings[0],
        "audit_trail": [
            {
                "step": "analyzing",
                "state": S.ANALYZING,
                "finding_count": len(findings),
                "first_rule_id": findings[0].get("rule_id"),
            }
        ],
    }


async def _reasoning(state: AgentState, ctx_agent) -> dict:
    finding = state.get("finding") or {}
    context = await ctx_agent.analyze(state, finding)
    await _emit(
        "agent.reasoning.completed",
        state,
        {
            "agent": getattr(ctx_agent, "name", "context-agent"),
            "rule_id": finding.get("rule_id"),
            "why_violation_matters": context.get("why_violation_matters", ""),
        },
    )
    return {
        "current_state": S.REASONING,
        "context_summary": context,
        "audit_trail": [
            {
                "step": "context_analysis",
                "state": S.REASONING,
                "agent": getattr(ctx_agent, "name", "context-agent"),
                "model": state.get("model_provider"),
                "rule_id": finding.get("rule_id"),
                "output": context,
            }
        ],
    }


async def _plan_remediation(state: AgentState, rem_agent) -> dict:
    finding = state.get("finding") or {}
    plan = await rem_agent.plan(
        finding=finding,
        context=state.get("context_summary") or {},
        backend_scan=state.get("backend_scan") or {},
        retry_count=int(state.get("retry_count") or 0),
    )
    action = plan.get("action", RemediationAction.ESCALATE)
    await _emit(
        "remediation.proposed",
        state,
        {
            "agent": getattr(rem_agent, "name", "remediation-agent"),
            "model": state.get("model_provider"),
            "rule_id": finding.get("rule_id"),
            "action": action,
            "confidence": plan.get("confidence"),
            "requires_review": plan.get("requires_human_review"),
        },
    )

    update: dict[str, Any] = {
        "current_state": S.REMEDIATION_PLANNED,
        "remediation_plan": plan,
        "audit_trail": [
            {
                "step": "remediation_planned",
                "state": S.REMEDIATION_PLANNED,
                "agent": getattr(rem_agent, "name", "remediation-agent"),
                "rule_id": finding.get("rule_id"),
                "action": action,
                "confidence": plan.get("confidence"),
                "reason": plan.get("reason", ""),
            }
        ],
    }

    escalate_reason = _escalation_reason(state, plan)
    if escalate_reason:
        return {**update, **_escalate(state, finding, escalate_reason, blocked=True)}

    if action == RemediationAction.SKIP:
        # Agent consciously declined to patch. That is only a block if the
        # finding is above the gate threshold.
        blocked = should_block(finding.get("severity", "LOW"), state.get("block_on_severity", "HIGH"))
        entry = {**finding, "skipped": True, "reason": plan.get("reason", "")}
        if blocked:
            return {
                **update,
                **_escalate(
                    state,
                    finding,
                    f"remediation skipped: {plan.get('reason', 'no reason given')}",
                    blocked=True,
                ),
            }
        return {**update, "resolved_findings": [entry]}

    return update


async def _mutating(state: AgentState, patcher) -> dict:
    finding = state.get("finding") or {}
    name = finding.get("artifact")
    patches = (state.get("remediation_plan") or {}).get("proposed_patches") or []

    if not name:
        return _escalate(
            state,
            finding,
            "finding has no artifact reference — cannot apply a mutation",
            state_update={"current_state": S.MUTATING},
        )

    source = _current_source(state, name)
    if source is None:
        return _escalate(
            state,
            finding,
            f"artifact '{name}' was not submitted with this release",
            state_update={"current_state": S.MUTATING},
        )

    artifact_type = artifact_type_of(source)
    try:
        document = decode_artifact(source)
    except ArtifactDecodeError as exc:
        return _escalate(
            state,
            finding,
            f"could not decode artifact '{name}': {exc}",
            state_update={"current_state": S.MUTATING},
        )

    try:
        patched, applied_ops = patcher.apply_patches(document, patches)
    except Exception as exc:  # noqa: BLE001 - a bad pointer must escalate, not crash
        # PatchEngine only converts KeyError/IndexError/TypeError into a
        # create-on-missing fallback, so a model-proposed pointer such as
        # ``/spec/containers/0/env/DATABASE_URL`` (a name, against a list) raises
        # ValueError straight through. That must fail the release, not the
        # process.
        return _escalate(
            state,
            finding,
            f"mutation could not be applied to '{name}': {type(exc).__name__}: {exc}",
            state_update={"current_state": S.MUTATING},
        )

    patched_artifact = {
        **source,
        "type": artifact_type,
        "name": name,
        "content": encode_content(patched, artifact_type),
    }

    await _emit(
        "remediation.applied",
        state,
        {
            "artifact": name,
            "rule_id": finding.get("rule_id"),
            "patch_count": len(applied_ops),
        },
    )
    return {
        "current_state": S.MUTATING,
        "patches_applied": patches,
        "patched_artifacts": _merge_patched(state, patched_artifact),
        "audit_trail": [
            {
                "step": "mutation_applied",
                "state": S.MUTATING,
                "artifact": name,
                "patches": patches,
                "applied_ops": applied_ops,
            }
        ],
    }


async def _compatibility_check(state: AgentState) -> dict:
    finding = state.get("finding") or {}
    backend_scan = state.get("backend_scan") or {}
    patches = state.get("patches_applied") or []

    if not patches or not backend_scan:
        return {
            "current_state": S.COMPATIBILITY_CHECK,
            "compatibility_result": "SKIPPED",
            "compatibility_mismatches": [],
            "audit_trail": [
                {
                    "step": "compatibility_check",
                    "state": S.COMPATIBILITY_CHECK,
                    "verdict": "SKIPPED",
                    "reason": "no backend profile submitted" if not backend_scan else "no patches",
                }
            ],
        }

    result = await run_compatibility_check(
        backend_scan=backend_scan,
        mutations_applied=patches,
        patched_artifact=_current_patched(state, finding.get("artifact")),
    )
    return {
        "current_state": S.COMPATIBILITY_CHECK,
        "compatibility_result": result.get("verdict", "SKIPPED"),
        "compatibility_mismatches": result.get("mismatches", []),
        "audit_trail": [
            {
                "step": "compatibility_check",
                "state": S.COMPATIBILITY_CHECK,
                "verdict": result.get("verdict"),
                "mismatches": result.get("mismatches", []),
            }
        ],
    }


async def _verification(state: AgentState, verif_agent, opa, finding: dict) -> dict:
    if state.get("escalated"):
        return {"current_state": S.VERIFICATION, "verification_result": "SKIPPED"}

    rescan_findings, rescan_error = await _rescan(state, finding, opa)

    evaluation = await verif_agent.evaluate(
        finding=finding,
        remediation_plan=state.get("remediation_plan") or {},
        rescan_findings=rescan_findings,
        compatibility_result={
            "verdict": state.get("compatibility_result", "SKIPPED"),
            "mismatches": state.get("compatibility_mismatches", []),
        },
        retry_count=int(state.get("retry_count") or 0),
        max_retries=int(state.get("max_retries") or 0),
    )

    next_action = evaluation.get("next_action", NextAction.ESCALATE)
    diagnosis = evaluation.get("diagnosis", "")

    if state.get("compatibility_result") == Verdict.INCOMPATIBLE:
        # Enforced here as well as inside VerificationAgent. The agent is an
        # untrusted component: a model that returns "looks fine, ship it" must
        # not be able to wave through a patch the backend scanner rejected.
        next_action = NextAction.ESCALATE
        diagnosis = f"{diagnosis} (compatibility check reported INCOMPATIBLE)".strip()

    update: dict[str, Any] = {
        "current_state": S.RESCAN if evaluation.get("verdict") == Verdict.PASS else S.DIAGNOSE,
        "verification_result": Verdict.INCOMPATIBLE
        if state.get("compatibility_result") == Verdict.INCOMPATIBLE
        else evaluation.get("verdict", Verdict.FAIL),
        "verification_diagnosis": diagnosis,
        "agent_next_action": next_action,
        "last_rescan_findings": rescan_findings,
        "audit_trail": [
            {
                "step": "verification",
                "state": S.VERIFICATION,
                "agent": getattr(verif_agent, "name", "verification-agent"),
                "rule_id": finding.get("rule_id"),
                "verdict": evaluation.get("verdict"),
                "next_action": next_action,
                "diagnosis": diagnosis,
                "rescan_error": rescan_error,
                "rescan_finding_count": len(rescan_findings),
            }
        ],
    }

    if rescan_error:
        # The verifier's verdict was reached without evidence — it must not be
        # recorded as a PASS, or a caller reading the state sees a clean run.
        return {
            **update,
            "verification_result": Verdict.FAIL,
            "verification_diagnosis": f"OPA re-scan failed: {rescan_error}",
            **_escalate(state, finding, f"OPA re-scan failed: {rescan_error}", blocked=True),
        }

    if next_action == NextAction.RETRY:
        retry_safe = bool(evaluation.get("retry_safe"))
        retries_left = int(state.get("max_retries") or 0) > int(state.get("retry_count") or 0)
        if not retry_safe or not retries_left:
            reason = (
                evaluation.get("escalation_reason")
                or "verification proposed a retry that is not safe or no retries remain"
            )
            return {**update, **_escalate(state, finding, reason, blocked=True)}
        return {**update, "retry_count": int(state.get("retry_count") or 0) + 1}

    if next_action == NextAction.ESCALATE:
        reason = (
            evaluation.get("escalation_reason")
            or (
                "compatibility check reported INCOMPATIBLE — the patch would break "
                "the application and cannot ship"
                if state.get("compatibility_result") == Verdict.INCOMPATIBLE
                else "verification escalated to human review"
            )
        )
        return {**update, **_escalate(state, finding, reason, blocked=True)}

    if evaluation.get("verdict") == Verdict.PASS:
        return {**update, "resolved_findings": [{**finding, "verdict": Verdict.PASS}]}

    # GATE on a FAIL verdict without escalating: the patch did not clear the
    # finding, so it counts as unresolved and the gate decides its severity.
    return {**update, "blocked_findings": [_blocked_entry(state, finding, evaluation.get("diagnosis", ""))]}


def _next_finding(state: AgentState) -> dict:
    pending = list(state.get("pending") or [])
    remaining = pending[1:]
    if not remaining:
        return {
            "current_state": S.GATE,
            "pending": [],
            "audit_trail": [{"step": "findings_drained", "state": S.GATE, "remaining": 0}],
        }
    return {
        "current_state": S.FINDINGS_FOUND,
        "pending": remaining,
        "finding": remaining[0],
        "context_summary": {},
        "remediation_plan": {},
        "patches_applied": [],
        "compatibility_result": "SKIPPED",
        "compatibility_mismatches": [],
        "verification_result": "PENDING",
        "verification_diagnosis": "",
        "agent_next_action": "",
        "retry_count": 0,
        "audit_trail": [
            {
                "step": "next_finding",
                "state": S.FINDINGS_FOUND,
                "rule_id": remaining[0].get("rule_id"),
                "remaining": len(remaining),
            }
        ],
    }


def _gate(state: AgentState) -> dict:
    if state.get("escalated") or state.get("blocked_findings"):
        decision = GateDecision.BLOCK
    elif state.get("patches_applied") or state.get("patched_artifacts"):
        decision = GateDecision.PATCHED
    else:
        decision = GateDecision.ALLOW

    return {
        "current_state": S.GATE,
        "decision": decision,
        "audit_trail": [
            {
                "step": "gate",
                "state": S.GATE,
                "decision": decision,
                "mutations_applied": len(state.get("patches_applied") or []),
                "blocked": len(state.get("blocked_findings") or []),
                "escalated": bool(state.get("escalated")),
            }
        ],
    }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _route_after_plan(state: AgentState) -> str:
    """Escalation blocks; a SKIP moves on; only a real PATCH mutates."""
    if state.get("escalated"):
        return GateDecision.BLOCK
    action = (state.get("remediation_plan") or {}).get("action")
    if action == RemediationAction.SKIP:
        # Routing a SKIP through ``mutating`` would apply an empty patch list
        # and report the artifact as patched — a fix that changed nothing.
        return NextAction.NEXT_FINDING
    return "mutating"


def _route_after_verification(state: AgentState) -> str:
    if state.get("escalated"):
        return GateDecision.BLOCK
    action = state.get("agent_next_action") or NextAction.NEXT_FINDING
    if action == NextAction.RETRY:
        return "plan_remediation"
    return "next_finding"


def _escalation_reason(state: AgentState, plan: dict) -> str:
    action = plan.get("action", RemediationAction.ESCALATE)
    if action == RemediationAction.ESCALATE:
        return plan.get("reason") or "remediation agent requested escalation"
    if plan.get("requires_human_review"):
        return plan.get("reason") or "remediation plan requires human review"

    threshold = float(state.get("confidence_threshold") or 0.0)
    confidence = float(plan.get("confidence") or 0.0)
    if confidence < threshold:
        return (
            f"remediation confidence {confidence:.2f} is below the "
            f"{threshold:.2f} threshold"
        )
    return ""


def _escalate(
    state: AgentState,
    finding: dict,
    reason: str,
    blocked: bool = True,
    state_update: dict | None = None,
) -> dict:
    update: dict[str, Any] = {
        "escalated": True,
        "escalation_reason": reason,
        "audit_trail": [
            {
                "step": "agent_escalated",
                "state": state.get("current_state"),
                "rule_id": finding.get("rule_id"),
                "reason": reason,
            }
        ],
    }
    if blocked:
        update["blocked_findings"] = [_blocked_entry(state, finding, reason)]
    if state_update:
        update.update(state_update)
    return update


def _blocked_entry(state: AgentState, finding: dict, reason: str) -> dict:
    return {
        **finding,
        "escalation_reason": reason,
        "compatibility_result": state.get("compatibility_result", "SKIPPED"),
    }


def _current_source(state: AgentState, name: str) -> dict | None:
    """The artifact to mutate: its already-patched form if one exists."""
    return _current_patched(state, name) or find_artifact(state.get("artifacts") or [], name)


def _current_patched(state: AgentState, name: str | None) -> dict | None:
    if not name:
        return None
    return find_artifact(state.get("patched_artifacts") or [], name)


def _merge_patched(state: AgentState, patched: dict) -> list[dict]:
    merged = [
        a for a in (state.get("patched_artifacts") or []) if a.get("name") != patched.get("name")
    ]
    merged.append(patched)
    return merged


async def _rescan(state: AgentState, finding: dict, opa) -> tuple[list[dict], str]:
    """Re-evaluate the patched artifact through OPA. Returns (findings, error)."""
    artifact = _current_patched(state, finding.get("artifact")) or _current_source(
        state, finding.get("artifact") or ""
    )
    if artifact is None:
        return [], "patched artifact unavailable for re-scan"

    if not await opa.health():
        return [], "OPA policy engine unavailable during re-scan"

    try:
        document = decode_artifact(artifact)
    except ArtifactDecodeError as exc:
        return [], f"could not decode patched artifact: {exc}"

    try:
        return await opa.evaluate_deny(policy_path_for(artifact_type_of(artifact)), document), ""
    except Exception as exc:  # noqa: BLE001 - OPA transport errors must not crash the loop
        return [], f"{type(exc).__name__}: {exc}"


async def _with_agent_timing(node: str, fn, state: AgentState, *args):
    """Run a node, recording agent latency and never letting metrics break it."""
    started = time.perf_counter()
    try:
        return await fn(state, *args)
    finally:
        AGENT_DURATION.labels(agent_name=_AGENT_FOR_NODE.get(node, node)).observe(
            time.perf_counter() - started
        )


async def _emit(event_type: str, state: AgentState, payload: dict) -> None:
    await publish_event(
        event_type,
        {
            "pipeline_id": state.get("pipeline_id", ""),
            "state": state.get("current_state"),
            **payload,
        },
    )
