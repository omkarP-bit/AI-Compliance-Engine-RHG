"""State contract for the LangGraph release-hardening loop.

The spec sketched this as a plain ``@dataclass``. That does not work: LangGraph
1.x passes a *dict* into every node and returns a *dict* from ``ainvoke`` even
when the schema is a dataclass, so ``result.decision`` in the orchestrator would
raise ``AttributeError``. The schema is therefore a ``TypedDict`` — which still
supports ``AgentState(pipeline_id=...)`` construction, and lets us attach
``Annotated`` reducers for the append-only audit lists.

The spec also only ever processed ``state.findings[0]``, silently dropping every
finding after the first. ``pending``/``finding`` add a real work queue so a
manifest with three violations gets three remediation cycles, while the
original field names (``findings``, ``patches_applied``, ``escalated``, ...)
are preserved for consumers.
"""

from __future__ import annotations

import operator
import os
from typing import Annotated, Any, TypedDict


# Canonical state names emitted in ``current_state`` and audit trail entries.
class S(str):
    RECEIVED = "RECEIVED"
    ANALYZING = "ANALYZING"
    POLICY_CHECK = "POLICY_CHECK"
    FINDINGS_FOUND = "FINDINGS_FOUND"
    REASONING = "REASONING"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    MUTATING = "MUTATING"
    COMPATIBILITY_CHECK = "COMPATIBILITY_CHECK"
    VERIFICATION = "VERIFICATION"
    DIAGNOSE = "DIAGNOSE"
    RESCAN = "RESCAN"
    GATE = "GATE"


#: Actions a remediation plan may request.
class RemediationAction(str):
    PATCH = "PATCH"
    SKIP = "SKIP"
    ESCALATE = "ESCALATE"


#: Routing decisions a verification result may request.
class NextAction(str):
    GATE = "GATE"
    RETRY = "RETRY"
    ESCALATE = "ESCALATE"
    NEXT_FINDING = "NEXT_FINDING"


#: Verification verdicts.
class Verdict(str):
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPATIBLE = "INCOMPATIBLE"


#: Final gate decisions.
class GateDecision(str):
    PENDING = "PENDING"
    ALLOW = "ALLOW"
    PATCHED = "PATCHED"
    BLOCK = "BLOCK"


#: Findings the agentic loop will not attempt to mutate on its own.
NON_PATCHABLE_SEVERITIES = frozenset({"CRITICAL"})

DEFAULT_MAX_RETRIES = 3
DEFAULT_CONFIDENCE_THRESHOLD = 0.85
DEFAULT_BLOCK_ON_SEVERITY = "HIGH"


class AgentState(TypedDict, total=False):
    """State threaded through the release graph.

    Fields suffixed ``_appended`` are reducers: a node that returns one of them
    has its value *appended* to the channel rather than replacing it. Every
    other field is replaced by whatever the node returns.
    """

    # ---- input -----------------------------------------------------------
    pipeline_id: str
    environment: str
    artifacts: list[dict]
    backend_scan: dict
    model_provider: str
    max_retries: int
    confidence_threshold: float
    block_on_severity: str

    # ---- runtime ---------------------------------------------------------
    current_state: str
    findings: list[dict]
    pending: list[dict]
    finding: dict
    context_summary: dict
    remediation_plan: dict
    patches_applied: list[dict]
    compatibility_result: str
    compatibility_mismatches: list[dict]
    verification_result: str
    verification_diagnosis: str
    agent_next_action: str
    retry_count: int
    escalated: bool
    escalation_reason: str
    last_rescan_findings: list[dict]

    # ---- accumulators (reducer-backed) ----------------------------------
    audit_trail: Annotated[list, operator.add]
    resolved_findings: Annotated[list, operator.add]
    blocked_findings: Annotated[list, operator.add]

    # Latest patched version of every artifact touched this run, one entry per
    # artifact name. Deliberately NOT a reducer: a second finding on the same
    # artifact must supersede the first patch, not append beside it.
    patched_artifacts: list[dict]

    # ---- output ----------------------------------------------------------
    decision: str
    risk_score: float
    overall_severity: str


def env_int(name: str, default: int) -> int:
    """Read an int from the environment, falling back on anything unparseable."""
    try:
        return int(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default


def initial_state(
    pipeline_id: str,
    environment: str = "production",
    artifacts: list[dict] | None = None,
    backend_scan: dict | None = None,
    model_provider: str = "nebius",
    max_retries: int | None = None,
    confidence_threshold: float | None = None,
    block_on_severity: str | None = None,
    findings: list[dict] | None = None,
) -> AgentState:
    """Build a fully-populated starting state with every accumulator seeded.

    Reducer-backed channels start as ``None`` unless seeded, and reading one
    before any node writes it is a common source of ``TypeError`` deep inside
    the graph — so seed them here instead.

    ``max_retries``, ``confidence_threshold`` and ``block_on_severity`` fall back
    to ``AGENT_MAX_RETRIES``, ``AGENT_CONFIDENCE_THRESHOLD`` and
    ``BLOCK_ON_SEVERITY`` when not passed explicitly.
    """
    found = list(findings or [])
    return AgentState(
        pipeline_id=pipeline_id,
        environment=environment,
        artifacts=list(artifacts or []),
        backend_scan=dict(backend_scan or {}),
        model_provider=model_provider,
        max_retries=env_int("AGENT_MAX_RETRIES", DEFAULT_MAX_RETRIES)
        if max_retries is None
        else max_retries,
        confidence_threshold=env_float(
            "AGENT_CONFIDENCE_THRESHOLD", DEFAULT_CONFIDENCE_THRESHOLD
        )
        if confidence_threshold is None
        else confidence_threshold,
        block_on_severity=(block_on_severity or os.environ.get("BLOCK_ON_SEVERITY") or DEFAULT_BLOCK_ON_SEVERITY),
        current_state=S.RECEIVED,
        findings=found,
        pending=list(found),
        finding={},
        context_summary={},
        remediation_plan={},
        patches_applied=[],
        compatibility_result="SKIPPED",
        compatibility_mismatches=[],
        verification_result="PENDING",
        verification_diagnosis="",
        agent_next_action="",
        retry_count=0,
        escalated=False,
        escalation_reason="",
        last_rescan_findings=[],
        audit_trail=[],
        resolved_findings=[],
        blocked_findings=[],
        patched_artifacts=[],
        decision=GateDecision.PENDING,
        risk_score=0.0,
        overall_severity="INFO",
    )


def severity_rank(severity: str) -> int:
    """Order severities for gate decisions. Unknown values rank lowest."""
    return {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }.get((severity or "").upper(), 0)


def should_block(severity: str, block_on: str) -> bool:
    """Whether a finding of ``severity`` blocks on a ``block_on`` threshold."""
    return severity_rank(severity) >= severity_rank(block_on)


def state_summary(state: dict[str, Any]) -> str:
    """One-line, log-safe description of a state for the audit trail."""
    return (
        f"state={state.get('current_state', '?')} "
        f"finding={state.get('finding', {}).get('rule_id', '-')} "
        f"pending={len(state.get('pending') or [])} "
        f"retry={state.get('retry_count', 0)}"
    )
