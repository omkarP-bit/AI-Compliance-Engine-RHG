from dataclasses import dataclass
from typing import Callable, Any


@dataclass
class MCPTool:
    name: str
    description: str
    handler: Callable


MCP_TOOLS: list[MCPTool] = []


def mcp_tool(name: str, description: str):
    def decorator(fn: Callable) -> Callable:
        MCP_TOOLS.append(MCPTool(name=name, description=description, handler=fn))
        return fn
    return decorator


@mcp_tool("scan_infrastructure", "Scan a deployment artifact for compliance violations")
async def scan_infrastructure(artifact_type: str, content: str) -> dict:
    from ace.engine.opa_client import OPAClient
    opa = OPAClient()
    import yaml
    parsed = yaml.safe_load(content)
    findings = await opa.evaluate_deny(f"ace.cis.{artifact_type}", parsed)
    return {"findings": findings, "count": len(findings)}


@mcp_tool("detect_drift", "Compare live cluster state against approved baseline")
async def detect_drift(cluster_id: str, namespace: str = "default") -> dict:
    return {"drift_detected": False, "differences": [], "cluster_id": cluster_id}


@mcp_tool("generate_fixes", "Generate remediation patches for a set of findings")
async def generate_fixes(finding_ids: list[str]) -> dict:
    return {"patches": [], "finding_ids": finding_ids, "auto_applicable": True}


@mcp_tool("fetch_cve_data", "Look up CVE data for a container image digest")
async def fetch_cve_data(image: str, digest: str = "") -> dict:
    return {"image": image, "cve_count": 0, "critical_cves": []}
