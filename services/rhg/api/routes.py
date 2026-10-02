import base64
import copy
import json
import os
from collections.abc import AsyncGenerator
from typing import Annotated

import httpx
from ace.alerts.router import AlertPayload, AlertRouter, AlertSeverity
from ace.metrics.prometheus import track_gate_decision
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from rhg.gate.evaluator import GateEvaluator
from rhg.mutator.patch_engine import PatchEngine

router = APIRouter(prefix="/rhg", tags=["RHG"])
gate = GateEvaluator(
    block_on=os.environ.get("BLOCK_ON_SEVERITY", "HIGH"),
    max_mutation_retries=int(os.environ.get("MAX_MUTATION_RETRIES", "3")),
)
ACE_URL = os.environ.get("ACE_URL", "http://localhost:8000")
alert_router = AlertRouter()


def _dispatch_alert(background_tasks: BackgroundTasks, payload: AlertPayload) -> None:
    background_tasks.add_task(alert_router.dispatch, payload)


class ArtifactInput(BaseModel):
    type: str
    name: str
    content: str


class BackendFile(BaseModel):
    language: str = "unknown"
    filename: str
    content: str


class SubmitRequest(BaseModel):
    pipeline_id: str
    repo: str = "unknown/repo"
    branch: str = "main"
    environment: str = "production"
    artifacts: list[ArtifactInput]
    backend_source: list[BackendFile] = []


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
    compatibility_verdict: str
    ops_notified: bool
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


def _pick_verdict(new: str, current: str) -> str:
    """Pick the more serious verdict. INCOMPATIBLE > COMPATIBLE > SKIPPED."""
    rank = {"INCOMPATIBLE": 2, "COMPATIBLE": 1, "SKIPPED": 0}
    return new if rank.get(new, 0) > rank.get(current, 0) else current


async def _check_compatibility(
    client: httpx.AsyncClient,
    request: SubmitRequest,
    scan: dict,
    patched: dict,
    patches: list[dict],
) -> tuple[str, list[dict]]:
    """Return (verdict, mismatches) from the ACE compatibility checker."""
    backend_scan = scan.get("backend_scan") or {}
    if not request.backend_source or not backend_scan:
        return "SKIPPED", []
    try:
        resp = await client.post(
            f"{ACE_URL}/ace/compatibility-check",
            json={
                "pipeline_id": request.pipeline_id,
                "patched_artifact": patched,
                "backend_scan": backend_scan,
                "mutations_applied": patches,
            },
        )
        if resp.status_code != 200:
            return "SKIPPED", []
        data = resp.json()
        return data.get("verdict", "COMPATIBLE"), data.get("mismatches", [])
    except Exception:  # noqa: BLE001
        return "SKIPPED", []


async def _notify_mutation(client: httpx.AsyncClient, request: SubmitRequest, finding: dict, patches: list[dict], verdict: str) -> bool:
    try:
        resp = await client.post(
            f"{ACE_URL}/ace/notify-mutation",
            json={
                "pipeline_id": request.pipeline_id,
                "repo": request.repo,
                "branch": request.branch,
                "environment": request.environment,
                "finding": finding,
                "patches": patches,
                "compatibility_verdict": verdict,
            },
        )
        return resp.status_code == 200
    except Exception:  # noqa: BLE001
        return False


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
    escalated_findings: list[dict] = []
    compatibility_verdict = "SKIPPED"
    ops_notified = False
    retry_count = start_retry
    current_scan = copy.deepcopy(initial_scan)

    for artifact_input in request.artifacts:
        raw_content = base64.b64decode(artifact_input.content).decode()
        try:
            import yaml
            docs = list(yaml.safe_load_all(raw_content))
            artifact_dict = docs[0] if docs else {}
        except (yaml.YAMLError, OSError):
            try:
                artifact_dict = json.loads(raw_content)
            except (json.JSONDecodeError, OSError):
                artifact_dict = {}

        normalized = _normalize_kubernetes_artifact(copy.deepcopy(artifact_dict))
        artifact_findings = [
            f for f in patchable_findings if f.get("artifact") == artifact_input.name
        ]

        artifact_patches = []
        for finding in artifact_findings:
            mutate_resp = await client.post(
                f"{ACE_URL}/ace/mutate",
                json={
                    "artifact_type": artifact_input.type,
                    "artifact": normalized,
                    "finding_ids": [finding.get("id", "")],
                },
            )
            if mutate_resp.status_code == 200:
                mutate_data = mutate_resp.json()
                artifact_patches.extend(mutate_data.get("patches", []))

        if not artifact_patches:
            continue

        deduplicated = _deduplicate_patches(artifact_patches)
        patched_dict, ops = PatchEngine.apply_patches(normalized, deduplicated)

        verdict, mismatches = await _check_compatibility(
            client, request, initial_scan, patched_dict, deduplicated
        )
        compatibility_verdict = _pick_verdict(verdict, compatibility_verdict)

        if verdict == "INCOMPATIBLE":
            for finding in artifact_findings:
                escalated_findings.append({
                    **finding,
                    "compat_mismatches": mismatches,
                    "escalation_reason": "mutation incompatible with backend",
                })
            continue  # do not commit this patch

        all_patches.extend(deduplicated)
        patched_content = yaml.dump(patched_dict) if _is_yaml(artifact_input.name) else json.dumps(patched_dict)
        patched_artifacts_output.append(PatchedArtifact(
            name=artifact_input.name,
            content=base64.b64encode(patched_content.encode()).decode(),
            patches_applied=ops,
        ))
        total_mutations += len(ops)

        for finding in artifact_findings:
            if await _notify_mutation(client, request, finding, deduplicated, verdict):
                ops_notified = True

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
                remaining_patchable = [
                    f for f in post_findings
                    if f.get("patchable", False) and f.get("artifact") not in [pa.name for pa in patched_artifacts_output]
                ]
                if remaining_patchable:
                    result = await _run_mutation_pipeline(
                        client, request, post_scan, remaining_patchable, retry_count
                    )
                    result["total_mutations"] += total_mutations
                    result["patched_artifacts_output"] = patched_artifacts_output + result["patched_artifacts_output"]
                    result["escalated_findings"] = escalated_findings + result["escalated_findings"]
                    result["compatibility_verdict"] = _pick_verdict(result["compatibility_verdict"], compatibility_verdict)
                    result["ops_notified"] = ops_notified or result["ops_notified"]
                    return result

            current_scan = post_scan

    return {
        "total_mutations": total_mutations,
        "all_patches": all_patches,
        "patched_artifacts_output": patched_artifacts_output,
        "retry_count": retry_count,
        "final_scan_data": current_scan,
        "escalated_findings": escalated_findings,
        "compatibility_verdict": compatibility_verdict,
        "ops_notified": ops_notified,
    }


def _normalize_kubernetes_artifact(raw: dict) -> dict:
    kind = raw.get("kind", "")
    spec = dict(raw.get("spec", {}))
    if kind in ("Deployment", "DaemonSet", "StatefulSet", "CronJob", "Job"):
        template_spec = spec.get("template", {}).get("spec", {})
        spec["containers"] = template_spec.get("containers", [])
        spec["initContainers"] = template_spec.get("initContainers", [])
        spec["hostNetwork"] = template_spec.get("hostNetwork", False)
        spec["hostPID"] = template_spec.get("hostPID", False)
    return {"apiVersion": raw.get("apiVersion"), "kind": kind, "metadata": raw.get("metadata", {}), "spec": spec}


async def _call_ace_scan(client: httpx.AsyncClient, request: SubmitRequest) -> dict:
    scan_resp = await client.post(
        f"{ACE_URL}/ace/scan",
        json=request.model_dump(),
    )
    if scan_resp.status_code != 200:
        raise HTTPException(502, f"ACE scan failed (HTTP {scan_resp.status_code})")
    return scan_resp.json()


@router.post("/submit", response_model=SubmitResponse)
async def submit(request: SubmitRequest, ace_client: Annotated[httpx.AsyncClient, Depends(get_ace_client)], background_tasks: BackgroundTasks) -> SubmitResponse:
    scan_data = await _call_ace_scan(ace_client, request)

    findings = scan_data.get("findings", [])
    patchable_findings = [f for f in findings if f.get("patchable", False)]
    non_patchable = [f for f in findings if not f.get("patchable", False)]

    total_mutations = 0
    patched_artifacts_output: list[PatchedArtifact] = []
    retry_count = 0
    compatibility_verdict = "SKIPPED"
    ops_notified = False
    escalated_findings: list[dict] = []

    if patchable_findings:
        result = await _run_mutation_pipeline(
            ace_client, request, scan_data, patchable_findings, 0
        )
        total_mutations = result["total_mutations"]
        patched_artifacts_output = result["patched_artifacts_output"]
        retry_count = result["retry_count"]
        scan_data = result["final_scan_data"]
        findings = scan_data.get("findings", [])
        compatibility_verdict = result["compatibility_verdict"]
        ops_notified = result["ops_notified"]
        escalated_findings = result["escalated_findings"]

    all_findings_post = list(findings) + non_patchable + escalated_findings
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

    track_gate_decision(gate_result.decision.value, request.environment)
    _dispatch_alert(background_tasks, AlertPayload(
        event_type="gate.decision",
        pipeline_id=request.pipeline_id,
        repo=request.repo,
        environment=request.environment,
        severity=AlertSeverity[overall_severity],
        findings_count=len(all_findings_post),
        blocking_rules=[f.get("rule_id", "?") for f in gate_result.blocking_findings],
        decision=gate_result.decision.value,
        report_url=report_url,
        mutation_count=total_mutations,
        escalation_reason="; ".join(f.get("message", "") for f in gate_result.blocking_findings),
    ))

    return SubmitResponse(
        decision=gate_result.decision.value,
        pipeline_id=request.pipeline_id,
        scan_id=scan_data.get("scan_id", ""),
        mutations_applied=total_mutations,
        mutator_retries=retry_count,
        compatibility_verdict=compatibility_verdict,
        ops_notified=ops_notified,
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