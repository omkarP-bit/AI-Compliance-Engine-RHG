import base64
import os
import json
import copy
from typing import AsyncGenerator
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import httpx

from rhg.gate.evaluator import GateEvaluator
from rhg.mutator.patch_engine import PatchEngine

router = APIRouter(prefix="/rhg", tags=["RHG"])
gate = GateEvaluator(
    block_on=os.environ.get("BLOCK_ON_SEVERITY", "HIGH"),
    max_mutation_retries=int(os.environ.get("MAX_MUTATION_RETRIES", "3")),
)
ACE_URL = os.environ.get("ACE_URL", "http://localhost:8000")


class ArtifactInput(BaseModel):
    type: str
    name: str
    content: str


class SubmitRequest(BaseModel):
    pipeline_id: str
    repo: str = "unknown/repo"
    branch: str = "main"
    environment: str = "production"
    artifacts: list[ArtifactInput]


class PatchedArtifact(BaseModel):
    name: str
    content: str
    patches_applied: list[str]


class SubmitResponse(BaseModel):
    decision: str
    pipeline_id: str
    scan_id: str
    mutations_applied: int
    mutator_retries: int
    blocking_findings: list[dict]
    patched_artifacts: list[PatchedArtifact]
    report_url: str


async def get_ace_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        yield client


def _deduplicate_patches(patches: list[dict]) -> list[dict]:
    seen_paths: set[str] = set()
    result = []
    for p in patches:
        key = f"{p.get('op', '')}:{p.get('path', '')}"
        if key not in seen_paths:
            seen_paths.add(key)
            result.append(p)
    return result


def _is_yaml(filename: str) -> bool:
    return filename.endswith((".yaml", ".yml"))


def _infer_type(filename: str) -> str:
    if filename.endswith((".yaml", ".yml")):
        return "kubernetes"
    if filename.endswith((".tf", ".tf.json", "tfplan.json")):
        return "terraform"
    if filename == "Dockerfile" or filename.endswith(".dockerfile"):
        return "dockerfile"
    return "kubernetes"


async def _run_mutation_pipeline(
    client: httpx.AsyncClient,
    request: SubmitRequest,
    initial_scan: dict,
    patchable_findings: list[dict],
    start_retry: int,
) -> dict:
    total_mutations = 0
    all_patches = []
    patched_artifacts_output: list[PatchedArtifact] = []
    retry_count = start_retry
    current_scan = copy.deepcopy(initial_scan)

    for artifact_input in request.artifacts:
        raw_content = base64.b64decode(artifact_input.content).decode()
        try:
            import yaml
            artifact_dict = yaml.safe_load(raw_content)
        except Exception:
            artifact_dict = json.loads(raw_content)

        artifact_patches = []
        for finding in patchable_findings:
            if finding.get("artifact") == artifact_input.name:
                mutate_resp = await client.post(
                    f"{ACE_URL}/ace/mutate",
                    json={
                        "artifact_type": artifact_input.type,
                        "artifact": artifact_dict,
                        "finding_ids": [finding.get("id", "")],
                    },
                )
                if mutate_resp.status_code == 200:
                    mutate_data = mutate_resp.json()
                    artifact_patches.extend(mutate_data.get("patches", []))

        if artifact_patches:
            deduplicated = _deduplicate_patches(artifact_patches)
            patched_dict, ops = PatchEngine.apply_patches(artifact_dict, deduplicated)
            all_patches.extend(deduplicated)
            patched_content = yaml.dump(patched_dict) if _is_yaml(artifact_input.name) else json.dumps(patched_dict)
            patched_artifacts_output.append(PatchedArtifact(
                name=artifact_input.name,
                content=base64.b64encode(patched_content.encode()).decode(),
                patches_applied=ops,
            ))
            total_mutations += len(ops)

    if total_mutations > 0:
        re_scan_artifacts = []
        for pa in patched_artifacts_output:
            re_scan_artifacts.append({
                "type": _infer_type(pa.name),
                "name": pa.name,
                "content": pa.content,
            })
        for orig in request.artifacts:
            if not any(pa.name == orig.name for pa in patched_artifacts_output):
                re_scan_artifacts.append(orig.model_dump())

        re_scan_resp = await client.post(
            f"{ACE_URL}/ace/scan",
            json={
                "pipeline_id": request.pipeline_id,
                "environment": request.environment,
                "artifacts": re_scan_artifacts,
                "policy_bundles": ["cis-kubernetes@v1.8"],
            },
        )
        if re_scan_resp.status_code == 200:
            post_scan = re_scan_resp.json()
            post_findings = post_scan.get("findings", [])
            pre_findings = current_scan.get("findings", [])

            if gate.should_retry_mutation(retry_count, pre_findings, post_findings):
                retry_count += 1
                remaining_patchable = [f for f in post_findings if f.get("patchable", False)]
                if remaining_patchable:
                    return await _run_mutation_pipeline(
                        client, request, post_scan, remaining_patchable, retry_count
                    )

            current_scan = post_scan

    return {
        "total_mutations": total_mutations,
        "all_patches": all_patches,
        "patched_artifacts_output": patched_artifacts_output,
        "retry_count": retry_count,
        "final_scan_data": current_scan,
    }


async def _call_ace_scan(client: httpx.AsyncClient, request: SubmitRequest) -> dict:
    scan_resp = await client.post(
        f"{ACE_URL}/ace/scan",
        json=request.model_dump(),
    )
    if scan_resp.status_code != 200:
        raise HTTPException(502, f"ACE scan failed (HTTP {scan_resp.status_code})")
    return scan_resp.json()


@router.post("/submit", response_model=SubmitResponse)
async def submit(request: SubmitRequest, ace_client: httpx.AsyncClient = Depends(get_ace_client)):
    scan_data = await _call_ace_scan(ace_client, request)

    findings = scan_data.get("findings", [])
    patchable_findings = [f for f in findings if f.get("patchable", False)]
    non_patchable = [f for f in findings if not f.get("patchable", False)]

    total_mutations = 0
    patched_artifacts_output: list[PatchedArtifact] = []
    retry_count = 0

    if patchable_findings:
        result = await _run_mutation_pipeline(
            ace_client, request, scan_data, patchable_findings, 0
        )
        total_mutations = result["total_mutations"]
        patched_artifacts_output = result["patched_artifacts_output"]
        retry_count = result["retry_count"]
        scan_data = result["final_scan_data"]
        findings = scan_data.get("findings", [])

    all_findings_post = list(findings) + non_patchable
    risk_score = scan_data.get("risk_score", 0.0)
    overall_severity = scan_data.get("overall_severity", "INFO")

    gate_result = gate.evaluate(
        findings=all_findings_post,
        risk_score=risk_score,
        overall_severity=overall_severity,
        mutations_applied=total_mutations,
    )

    report_url = (
        f"{os.environ.get('DASHBOARD_URL', 'http://localhost:3000')}"
        f"/report/{scan_data.get('scan_id', '')}"
    )

    return SubmitResponse(
        decision=gate_result.decision.value,
        pipeline_id=request.pipeline_id,
        scan_id=scan_data.get("scan_id", ""),
        mutations_applied=total_mutations,
        mutator_retries=retry_count,
        blocking_findings=[
            {
                "rule_id": f.get("rule_id", "?"),
                "severity": f.get("severity", "?"),
                "message": f.get("message", ""),
                "artifact": f.get("artifact", ""),
            }
            for f in gate_result.blocking_findings
        ],
        patched_artifacts=patched_artifacts_output,
        report_url=report_url,
    )


@router.get("/health")
async def health():
    return {"status": "ok", "service": "rhg"}
