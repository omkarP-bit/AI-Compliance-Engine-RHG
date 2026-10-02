from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from ace.agents.compatibility_agent import CompatibilityAgent
from ace.backend_scanner.extractor import BackendProfile

compat_router = APIRouter(prefix="/ace", tags=["Compatibility"])
agent = CompatibilityAgent()


class CompatibilityRequest(BaseModel):
    pipeline_id: str
    patched_artifact: dict = {}
    backend_scan: dict = {}
    mutations_applied: list[dict] = []


class Mismatch(BaseModel):
    mutation_path: str
    patched_value: Any = None
    backend_value: Any = None
    detail: str
    severity: str
    action: str  # ESCALATE | WARN | INFO


class CompatibilityResponse(BaseModel):
    compatible: bool
    verdict: str  # COMPATIBLE | INCOMPATIBLE | NEEDS_REVIEW
    mismatches: list[Mismatch]
    agent_reviewed: bool = False


def _as_backend_profile(scan: dict) -> BackendProfile:
    return BackendProfile(
        language=scan.get("language", "unknown"),
        port_bindings=[int(p) for p in scan.get("port_bindings", []) if str(p).isdigit()],
        env_vars_used=scan.get("env_vars_used", []),
        routes=scan.get("routes", []),
        frameworks=scan.get("frameworks", []),
    )


def _check_port(path: str, value: Any, op: str, profile: BackendProfile) -> Mismatch | None:
    if "containerPort" not in path and "port" not in path.lower():
        return None
    try:
        new_port = int(value)
    except (TypeError, ValueError):
        return None
    if profile.port_bindings and new_port not in profile.port_bindings:
        return Mismatch(
            mutation_path=path,
            patched_value=new_port,
            backend_value=profile.port_bindings,
            detail=(
                f"Backend binds to port(s) {profile.port_bindings} "
                f"but artifact now exposes port {new_port}"
            ),
            severity="HIGH",
            action="ESCALATE",
        )
    return None


def _check_env_removal(path: str, value: Any, op: str, profile: BackendProfile) -> Mismatch | None:
    if op != "remove":
        return None
    for env_var in profile.env_vars_used:
        if env_var.lower() in path.lower():
            return Mismatch(
                mutation_path=path,
                patched_value=value,
                backend_value=env_var,
                detail=(
                    f"Env var '{env_var}' was removed from the manifest "
                    f"but the backend references it"
                ),
                severity="HIGH",
                action="ESCALATE",
            )
    return None


def _check_probe_path(path: str, value: Any, op: str, profile: BackendProfile) -> Mismatch | None:
    if "probe" not in path.lower():
        return None
    route = str(value or "")
    if route and profile.routes and route not in profile.routes:
        return Mismatch(
            mutation_path=path,
            patched_value=value,
            backend_value=profile.routes,
            detail=f"Probe path '{route}' is not exposed by the backend routes {profile.routes}",
            severity="MEDIUM",
            action="WARN",
        )
    return None


async def run_compatibility_check(
    backend_scan: dict,
    mutations_applied: list[dict],
    patched_artifact: dict | None = None,
) -> dict[str, Any]:
    """Evaluate mutations against a backend profile without going through HTTP.

    This is the reusable core behind ``POST /ace/compatibility-check`` and it is
    what the LangGraph release loop calls directly (``ace.agents.graph``) — the
    loop must not issue an HTTP request to its own process to ask whether the
    patch it just applied is safe.

    Returns a plain dict with ``compatible``, ``verdict``, ``mismatches`` and
    ``agent_reviewed`` so callers can either use it directly or splat it into
    :class:`CompatibilityResponse`.
    """
    profile = _as_backend_profile(backend_scan)
    mismatches: list[Mismatch] = []

    for mutation in mutations_applied or []:
        path = mutation.get("path", "")
        value = mutation.get("value")
        op = mutation.get("op", "replace")

        for check in (_check_port, _check_env_removal, _check_probe_path):
            m = check(path, value, op, profile)
            if m:
                mismatches.append(m)

    verdict = "COMPATIBLE" if not mismatches else "INCOMPATIBLE"
    compatible = verdict == "COMPATIBLE"

    needs_review = any(m.action == "WARN" for m in mismatches) and not any(m.action == "ESCALATE" for m in mismatches)
    if needs_review:
        verdict = "NEEDS_REVIEW"
        compatible = False

    agent_result = await agent.review(mismatches, profile)
    return {
        "compatible": compatible,
        "verdict": verdict,
        "mismatches": [m.model_dump() for m in mismatches],
        "agent_reviewed": agent_result["reviewed"],
    }


@compat_router.post("/compatibility-check", response_model=CompatibilityResponse)
async def compatibility_check(req: CompatibilityRequest):
    return CompatibilityResponse(
        **await run_compatibility_check(
            backend_scan=req.backend_scan,
            mutations_applied=req.mutations_applied,
            patched_artifact=req.patched_artifact,
        )
    )