"""HTTP surface for the v3 agentic release loop (``POST /ace/agent``).

This endpoint is the agentic counterpart to ``POST /ace/scan``: it scans the
submitted artifacts exactly as ``/ace/scan`` does (single source of truth for
parsing and OPA evaluation), then hands the findings to the LangGraph release
loop in ``ace.agents.graph``. The loop reasons about each finding, proposes a
remediation, applies it through ``PatchEngine``, re-scans through OPA and routes
to ``ALLOW`` / ``PATCHED`` / ``BLOCK``.

The process boundary stays where the rest of ACE puts it: RHG (or any client)
reaches this endpoint over HTTP. ``run_release_loop`` is invoked in-process
here, so the loop has direct access to the OPA client and the event bus.

``_build_graph`` is the single seam tests (and any caller that wants a
policy-backed or stubbed agent set) replace; everything else runs for real.
"""

from __future__ import annotations

import os

from common.observability import get_report_url
from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

from ace.agents.graph import build_release_graph, run_release_loop
from ace.agents.state import initial_state
from ace.api.routes import ArtifactInput, BackendFile, ScanRequest, scan
from ace.metrics.prometheus import track_gate_decision

router = APIRouter(prefix="/ace", tags=["ACE"])

#: Compatibility verdicts ordered by severity, for picking the worst one a
#: multi-finding run produced.
_VERDICT_RANK = {"INCOMPATIBLE": 3, "NEEDS_REVIEW": 2, "COMPATIBLE": 1, "SKIPPED": 0}


class AgentRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    pipeline_id: str
    environment: str = "production"
    artifacts: list[ArtifactInput]
    policy_bundles: list[str] = ["cis-kubernetes@v1.8"]
    backend_source: list[BackendFile] = []
    model_provider: str | None = None
    max_retries: int | None = None
    confidence_threshold: float | None = None
    block_on_severity: str | None = None


class PatchedArtifactOut(BaseModel):
    name: str
    content: str
    patches_applied: list[str] = []


class AgentResponse(BaseModel):
    pipeline_id: str
    scan_id: str
    decision: str
    risk_score: float
    overall_severity: str
    mutations_applied: int
    compatibility_verdict: str
    escalated: bool
    escalation_reason: str
    findings: list[dict]
    blocked_findings: list[dict]
    resolved_findings: list[dict]
    patched_artifacts: list[PatchedArtifactOut]
    audit_trail: list[dict]
    report_url: str


def _build_graph(provider: str | None):
    """Build the compiled release graph. Replaced by tests."""
    return build_release_graph(provider=provider or os.environ.get("MODEL_PROVIDER", "nebius"))


def _worst_verdict(out: dict) -> str:
    """The most serious compatibility verdict the run recorded.

    The graph's ``compatibility_result`` is only the last finding's verdict, so a
    multi-finding run needs the audit trail scanned to surface an earlier
    ``INCOMPATIBLE``.
    """
    worst = "SKIPPED"
    for entry in out.get("audit_trail") or []:
        if entry.get("step") != "compatibility_check":
            continue
        verdict = entry.get("verdict") or "SKIPPED"
        if _VERDICT_RANK.get(verdict, 0) > _VERDICT_RANK.get(worst, 0):
            worst = verdict
    return worst


def _patches_by_artifact(out: dict) -> dict[str, list[str]]:
    """Map artifact name -> the mutation ops applied to it, in order."""
    applied: dict[str, list[str]] = {}
    for entry in out.get("audit_trail") or []:
        if entry.get("step") == "mutation_applied":
            name = entry.get("artifact", "")
            applied.setdefault(name, []).extend(entry.get("applied_ops") or [])
    return applied


@router.post("/agent", response_model=AgentResponse)
async def run_agent(request: AgentRequest) -> AgentResponse:
    scan_data = await scan(
        ScanRequest(
            pipeline_id=request.pipeline_id,
            environment=request.environment,
            artifacts=request.artifacts,
            policy_bundles=request.policy_bundles,
            backend_source=request.backend_source,
        )
    )

    state = initial_state(
        pipeline_id=request.pipeline_id,
        environment=request.environment,
        artifacts=[a.model_dump() for a in request.artifacts],
        backend_scan=scan_data.backend_scan,
        model_provider=request.model_provider or os.environ.get("MODEL_PROVIDER", "nebius"),
        max_retries=request.max_retries,
        confidence_threshold=request.confidence_threshold,
        block_on_severity=request.block_on_severity,
        findings=scan_data.findings,
    )

    out = await run_release_loop(_build_graph(request.model_provider), state)

    decision = out.get("decision", "BLOCK")
    track_gate_decision(decision, request.environment)

    patches = _patches_by_artifact(out)
    patched_artifacts = [
        PatchedArtifactOut(
            name=artifact.get("name", ""),
            content=artifact.get("content", ""),
            patches_applied=patches.get(artifact.get("name", ""), []),
        )
        for artifact in out.get("patched_artifacts") or []
    ]

    report_url = get_report_url()

    return AgentResponse(
        pipeline_id=request.pipeline_id,
        scan_id=scan_data.scan_id,
        decision=decision,
        risk_score=scan_data.risk_score,
        overall_severity=scan_data.overall_severity,
        mutations_applied=sum(len(ops) for ops in patches.values()),
        compatibility_verdict=_worst_verdict(out),
        escalated=bool(out.get("escalated")),
        escalation_reason=out.get("escalation_reason", ""),
        findings=scan_data.findings,
        blocked_findings=list(out.get("blocked_findings") or []),
        resolved_findings=list(out.get("resolved_findings") or []),
        patched_artifacts=patched_artifacts,
        audit_trail=list(out.get("audit_trail") or []),
        report_url=report_url,
    )
