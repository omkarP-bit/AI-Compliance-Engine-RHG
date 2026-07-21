import base64
import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ace.parsers.kubernetes import KubernetesParser
from ace.parsers.terraform import TerraformParser
from ace.parsers.dockerfile import DockerfileParser
from ace.parsers.helm import HelmParser
from ace.engine.opa_client import OPAClient
from ace.scoring.risk_scorer import score_findings

router = APIRouter(prefix="/ace", tags=["ACE"])
opa = OPAClient()

PARSERS = [KubernetesParser(), TerraformParser(), DockerfileParser(), HelmParser()]
POLICY_MAP = {
    "kubernetes": "ace/cis/kubernetes",
    "terraform": "ace/cis/terraform",
    "dockerfile": "ace/cis/docker",
    "helm": "ace/cis/kubernetes",
}


class ArtifactInput(BaseModel):
    type: str
    name: str
    content: str


class ScanRequest(BaseModel):
    pipeline_id: str
    environment: str = "production"
    artifacts: list[ArtifactInput]
    policy_bundles: list[str] = ["cis-kubernetes@v1.8"]


class ScanResponse(BaseModel):
    scan_id: str
    pipeline_id: str
    risk_score: float
    overall_severity: str
    findings: list[dict]


@router.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
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
    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        pipeline_id=request.pipeline_id,
        risk_score=risk.score,
        overall_severity=risk.severity.value,
        findings=all_findings,
    )
