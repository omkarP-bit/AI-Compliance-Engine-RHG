import base64
import copy
import os
import time
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ace.api.websocket import publish_event
from ace.engine.opa_client import OPAClient
from ace.metrics.prometheus import track_scan
<<<<<<< Updated upstream
from ace.parsers.docker_compose import DockerComposeParser
=======
from ace.notifier.mutation_notifier import MutationEvent, MutationNotifier
>>>>>>> Stashed changes
from ace.parsers.dockerfile import DockerfileParser
from ace.parsers.github_actions import GitHubActionsParser
from ace.parsers.helm import HelmParser
from ace.parsers.kubernetes import KubernetesParser
from ace.parsers.terraform import TerraformParser
from ace.scoring.risk_scorer import score_findings

router = APIRouter(prefix="/ace", tags=["ACE"])
opa = OPAClient(opa_url=os.environ.get("OPA_URL", "http://localhost:8181"))
notifier = MutationNotifier()

PARSERS = [
    GitHubActionsParser(),
    DockerComposeParser(),
    KubernetesParser(),
    TerraformParser(),
    DockerfileParser(),
    HelmParser(),
]
POLICY_MAP = {
    "kubernetes": "ace/cis/kubernetes",
    "terraform": "ace/cis/terraform",
    "dockerfile": "ace/cis/docker",
    "helm": "ace/cis/kubernetes",
    "docker_compose": "ace/cis/docker_compose",
    "github_actions": "ace/gha/security",
    "nist": "ace/nist",
}


class ArtifactInput(BaseModel):
    type: str
    name: str
    content: str


class BackendFile(BaseModel):
    language: str = "unknown"
    filename: str
    content: str


class ScanRequest(BaseModel):
    pipeline_id: str
    environment: str = "production"
    artifacts: list[ArtifactInput]
    policy_bundles: list[str] = ["cis-kubernetes@v1.8"]
    backend_source: list[BackendFile] = []


class ScanResponse(BaseModel):
    scan_id: str
    pipeline_id: str
    risk_score: float
    overall_severity: str
    findings: list[dict]
    backend_scan: dict = {}


class MutateRequest(BaseModel):
    artifact_type: str
    artifact: dict
    finding_ids: list[str]


class MutateResponse(BaseModel):
    patches: list[dict]
    patch_count: int
    before_snapshot: dict
    after_snapshot: dict


class ScanAndMutateResponse(BaseModel):
    scan_id: str
    pipeline_id: str
    risk_score: float
    overall_severity: str
    findings: list[dict]
    patches: list[dict]
    patch_count: int
    mutations_applied: list[str]
    before_snapshot: list[dict]


@router.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    start = time.time()
    if not await opa.health():
        raise HTTPException(503, "OPA policy engine unavailable")

    all_findings = []
    for artifact in request.artifacts:
        raw_content = base64.b64decode(artifact.content).decode()
        parser = next((p for p in PARSERS if p.supports(artifact.name)), None)
        if not parser:
            continue
        normalized = parser.parse(raw_content, artifact.name)
        policy_path = POLICY_MAP.get(normalized.artifact_type, "ace/cis/kubernetes")
        findings = await opa.evaluate_deny(policy_path, normalized.raw)
        for f in findings:
            f["artifact"] = artifact.name
        all_findings.extend(findings)

    risk = score_findings(all_findings, request.environment)
    backend_scan = {}
    if request.backend_source:
        from ace.backend_scanner.extractor import BackendExtractor

        profile = BackendExtractor().extract(
            [b.model_dump() for b in request.backend_source]
        )
        backend_scan = {
            "language": profile.language,
            "port_bindings": profile.port_bindings,
            "env_vars_used": profile.env_vars_used,
            "routes": profile.routes,
            "frameworks": profile.frameworks,
        }

    duration = time.time() - start
    outcome = "block" if risk.severity.value in ("CRITICAL", "HIGH") else "allow"
    track_scan(request.environment, outcome, duration, all_findings)
    await publish_event("scan.completed", {
        "scan_id": "",
        "pipeline_id": request.pipeline_id,
        "environment": request.environment,
        "risk_score": risk.score,
        "overall_severity": risk.severity.value,
        "finding_count": len(all_findings),
    })
    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        pipeline_id=request.pipeline_id,
        risk_score=risk.score,
        overall_severity=risk.severity.value,
        findings=all_findings,
        backend_scan=backend_scan,
    )


@router.post("/mutate", response_model=MutateResponse)
async def mutate(request: MutateRequest):
    if request.artifact_type == "kubernetes":
        artifact = _normalize_kubernetes(request.artifact)
    else:
        artifact = request.artifact
    policy_path = POLICY_MAP.get(request.artifact_type, "ace/cis/kubernetes")
    patches = await opa.evaluate_patch(policy_path, artifact)
    await publish_event("mutation.applied", {
        "artifact": request.artifact_type,
        "patch_count": len(patches),
        "finding_ids": request.finding_ids,
    })
    return MutateResponse(
        patches=patches,
        patch_count=len(patches),
        before_snapshot=copy.deepcopy(request.artifact),
        after_snapshot=artifact,
    )


def _normalize_kubernetes(raw: dict) -> dict:
    kind = raw.get("kind", "")
    spec = dict(raw.get("spec", {}))
    if kind in ("Deployment", "DaemonSet", "StatefulSet", "CronJob", "Job"):
        template_spec = spec.get("template", {}).get("spec", {})
        spec["containers"] = template_spec.get("containers", [])
        spec["initContainers"] = template_spec.get("initContainers", [])
        spec["hostNetwork"] = template_spec.get("hostNetwork", False)
        spec["hostPID"] = template_spec.get("hostPID", False)
    return {"apiVersion": raw.get("apiVersion"), "kind": kind, "metadata": raw.get("metadata", {}), "spec": spec}


@router.post("/scan-and-mutate", response_model=ScanAndMutateResponse)
async def scan_and_mutate(request: ScanRequest):
    start = time.time()
    scan_result = await scan(request)
    all_patches = []
    all_mutations = []
    before_snapshot = [a.model_dump() for a in request.artifacts]

    for artifact in request.artifacts:
        raw_content = base64.b64decode(artifact.content).decode()
        parser = next((p for p in PARSERS if p.supports(artifact.name)), None)
        if not parser:
            continue
        normalized = parser.parse(raw_content, artifact.name)
        policy_path = POLICY_MAP.get(normalized.artifact_type, "ace/cis/kubernetes")
        patches = await opa.evaluate_patch(policy_path, normalized.raw)
        for p in patches:
            p["artifact"] = artifact.name
        all_patches.extend(patches)

    for patch in all_patches:
        all_mutations.append(
            f"{patch.get('op', 'unknown')} {patch.get('path', '')} -> {patch.get('value', 'N/A')}"
        )

    duration = time.time() - start
    track_scan(request.environment, "patched", duration, scan_result.findings)
    await publish_event("scan.completed", {
        "scan_id": scan_result.scan_id,
        "pipeline_id": scan_result.pipeline_id,
        "environment": request.environment,
        "risk_score": scan_result.risk_score,
        "overall_severity": scan_result.overall_severity,
        "finding_count": len(scan_result.findings),
    })
    await publish_event("mutation.applied", {
        "patch_count": len(all_patches),
        "mutations_applied": len(all_mutations),
    })

    return ScanAndMutateResponse(
        scan_id=scan_result.scan_id,
        pipeline_id=scan_result.pipeline_id,
        risk_score=scan_result.risk_score,
        overall_severity=scan_result.overall_severity,
        findings=scan_result.findings,
        patches=all_patches,
        patch_count=len(all_patches),
        mutations_applied=all_mutations,
        before_snapshot=before_snapshot,
    )


class NotifyMutationRequest(BaseModel):
    pipeline_id: str
    repo: str
    branch: str = "main"
    environment: str = "production"
    finding: dict = {}
    patches: list[dict] = []
    compatibility_verdict: str = "SKIPPED"
    diff_url: str = ""
    review_url: str = ""


@router.post("/notify-mutation")
async def notify_mutation(req: NotifyMutationRequest):
    dashboard = os.environ.get("DASHBOARD_URL", "")
    event = MutationEvent(
        pipeline_id=req.pipeline_id,
        repo=req.repo,
        branch=req.branch,
        environment=req.environment,
        rule_id=req.finding.get("rule_id", "UNKNOWN"),
        rule_severity=req.finding.get("severity", "HIGH"),
        rule_description=req.finding.get("message", ""),
        artifact_name=req.finding.get("artifact", ""),
        patches=req.patches,
        compatibility_verdict=req.compatibility_verdict,
        diff_url=req.diff_url or f"{dashboard}/diff/{req.pipeline_id}",
        review_url=req.review_url or f"{dashboard}/review/{req.pipeline_id}",
    )
    await publish_event("ops.notified", {
        "pipeline_id": req.pipeline_id,
        "rule_id": event.rule_id,
        "artifact": event.artifact_name,
        "compatibility": event.compatibility_verdict,
    })
    results = await notifier.notify(event)
    return {"notified": bool(results), "channels": results}
