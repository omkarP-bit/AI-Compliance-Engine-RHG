"""RHG proxy for the v3 agentic release loop (``POST /rhg/agentic-submit``).

RHG is a client of ACE, exactly as it is for the v2 ``/rhg/submit`` pipeline:
this endpoint forwards the submitted release to ``ACE_URL/ace/agent`` and maps
the agent response onto the RHG response schema, records the gate-decision
metric and dispatches the same ``gate.decision`` alert the v2 path sends.

The decision is the graph's: RHG does not re-evaluate it. OPA remains the sole
policy authority inside ACE, and the graph's compatibility gate is enforced
there before any decision is returned.
"""

from __future__ import annotations

import os
from typing import Annotated

import httpx
from ace.alerts.router import AlertPayload, AlertSeverity, build_alert_router
from common.observability import get_report_url
from common.storage import ActivityRecord, get_storage_backend
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from rhg.api.routes import SubmitRequest, get_ace_client

router = APIRouter(prefix="/rhg", tags=["RHG"])
ACE_URL = os.environ.get("ACE_URL", "http://localhost:8000")
alert_router = build_alert_router()
_storage = get_storage_backend()


class PatchedArtifact(BaseModel):
    name: str
    content: str
    patches_applied: list[str] = []


class AgenticSubmitResponse(BaseModel):
    decision: str
    pipeline_id: str
    scan_id: str
    mutations_applied: int
    compatibility_verdict: str
    escalated: bool
    escalation_reason: str
    blocking_findings: list[dict]
    patchable_findings: list[dict] = []
    resolved_findings: list[dict] = []
    patched_artifacts: list[PatchedArtifact]
    audit_trail: list[dict]
    report_url: str


def _severity(name: str) -> AlertSeverity:
    return AlertSeverity.__members__.get((name or "INFO").upper(), AlertSeverity.INFO)


@router.post("/agentic-submit", response_model=AgenticSubmitResponse)
async def agentic_submit(
    request: SubmitRequest,
    ace_client: Annotated[httpx.AsyncClient, Depends(get_ace_client)],
    background_tasks: BackgroundTasks,
) -> AgenticSubmitResponse:
    try:
        resp = await ace_client.post(
            f"{ACE_URL}/ace/agent",
            json=request.model_dump(),
            timeout=300.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"ACE agent run failed: {exc}") from exc

    if resp.status_code != 200:
        raise HTTPException(502, f"ACE agent run failed (HTTP {resp.status_code})")

    data = resp.json()
    decision = data.get("decision", "BLOCK")
    findings = list(data.get("findings", []))
    blocked = list(data.get("blocked_findings", []))
    report_url = data.get("report_url", "") or get_report_url()

    try:
        from ace.metrics.prometheus import track_gate_decision

        track_gate_decision(decision, request.environment)
    except Exception:
        pass
    try:
        _storage.record_activity(
            ActivityRecord(
                event_type="gate.decision.agentic",
                scan_id=data.get("scan_id"),
                repo=request.repo,
                branch=request.branch,
                environment=request.environment,
                overall_severity=data.get("overall_severity"),
                findings_count=len(findings),
                mutations_applied=data.get("mutations_applied") or data.get("patched_count") or 0,
                gate_decision=decision,
                triggered_by="ci",
                artifact_count=len(request.artifacts),
            )
        )
    except Exception:
        pass
    background_tasks.add_task(
        alert_router.dispatch,
        AlertPayload(
            event_type="gate.decision",
            pipeline_id=request.pipeline_id,
            repo=request.repo,
            environment=request.environment,
            severity=_severity(data.get("overall_severity", "INFO")),
            findings_count=len(findings),
            blocking_rules=[f.get("rule_id", "?") for f in blocked],
            decision=decision,
            report_url=report_url,
            mutation_count=data.get("mutations_applied", 0),
            escalation_reason=data.get("escalation_reason", ""),
        ),
    )

    return AgenticSubmitResponse(
        decision=decision,
        pipeline_id=request.pipeline_id,
        scan_id=data.get("scan_id", ""),
        mutations_applied=data.get("mutations_applied", 0),
        compatibility_verdict=data.get("compatibility_verdict", "SKIPPED"),
        escalated=bool(data.get("escalated")),
        escalation_reason=data.get("escalation_reason", ""),
        blocking_findings=blocked,
        patchable_findings=[f for f in findings if f.get("patchable", False)],
        resolved_findings=list(data.get("resolved_findings", [])),
        patched_artifacts=[PatchedArtifact(**p) for p in data.get("patched_artifacts", [])],
        audit_trail=list(data.get("audit_trail", [])),
        report_url=report_url,
    )
