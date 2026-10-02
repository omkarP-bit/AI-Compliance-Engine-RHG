import base64

import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock

from rhg.api.routes import get_ace_client
from rhg.main import app

VULN_YAML = base64.b64encode(b"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vuln-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
""").decode()

BACKEND_SOURCE = [
    {"language": "python", "filename": "main.py",
     "content": base64.b64encode(b'from fastapi import FastAPI\napp = FastAPI()').decode()}
]

VULN_SCAN = {
    "scan_id": "scan-v2",
    "pipeline_id": "pipe-v2",
    "risk_score": 7.5,
    "overall_severity": "HIGH",
    "findings": [
        {"id": "f-001", "rule_id": "CIS-K8S-5.2.1", "severity": "HIGH",
         "message": "Privileged container", "artifact": "deploy.yaml", "patchable": True}
    ],
    "backend_scan": {
        "language": "python", "port_bindings": [8000],
        "env_vars_used": ["DATABASE_URL"], "routes": ["/health"],
    },
}

CLEAN_SCAN = {
    "scan_id": "scan-clean",
    "pipeline_id": "pipe-v2",
    "risk_score": 0.0,
    "overall_severity": "INFO",
    "findings": [],
    "backend_scan": {
        "language": "python", "port_bindings": [8000],
        "env_vars_used": ["DATABASE_URL"], "routes": ["/health"],
    },
}

MUTATE_RESULT = {
    "patches": [
        {"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False},
        {"op": "add", "path": "/spec/containers/0/securityContext/runAsNonRoot", "value": True},
    ],
    "patch_count": 2,
    "before_snapshot": {},
}


def _submit_body(backend=True):
    return {
        "pipeline_id": "pipe-v2",
        "repo": "org/svc",
        "branch": "main",
        "environment": "production",
        "artifacts": [{"type": "kubernetes", "name": "deploy.yaml", "content": VULN_YAML}],
        "backend_source": BACKEND_SOURCE if backend else [],
    }


def _mock_client(responses: list) -> AsyncMock:
    """Sequential responses for each POST call: scan, mutate, compat, notify, rescan."""
    idx = [0]
    client = AsyncMock(spec=httpx.AsyncClient)

    async def post(url, **kwargs):
        del kwargs
        resp = AsyncMock(spec=httpx.Response)
        resp.status_code = 200
        data = responses[min(idx[0], len(responses) - 1)]
        resp.json.return_value = data
        idx[0] += 1
        return resp

    client.post = post
    return client


@pytest.mark.asyncio
class TestRHGSubmitV2:
    async def test_patched_decision_notifies_ops(self):
        compat_ok = {"compatible": True, "verdict": "COMPATIBLE", "mismatches": []}
        responses = [VULN_SCAN, MUTATE_RESULT, compat_ok, {"notified": True}, CLEAN_SCAN]
        app.dependency_overrides[get_ace_client] = lambda: _mock_client(responses)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/rhg/submit", json=_submit_body())
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] == "PATCHED"
            assert data["compatibility_verdict"] == "COMPATIBLE"
            assert data["ops_notified"] is True
            assert data["mutations_applied"] == 2

        app.dependency_overrides.clear()

    async def test_block_on_incompatible_mutation(self):
        compat_bad = {
            "compatible": False, "verdict": "INCOMPATIBLE",
            "mismatches": [{"mutation_path": "/spec/containers/0/ports/0/containerPort",
                            "detail": "Backend binds to 8000 but artifact now exposes 8080"}],
        }
        responses = [VULN_SCAN, MUTATE_RESULT, compat_bad]
        app.dependency_overrides[get_ace_client] = lambda: _mock_client(responses)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/rhg/submit", json=_submit_body())
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] == "BLOCK"
            assert data["compatibility_verdict"] == "INCOMPATIBLE"
            assert data["mutations_applied"] == 0
            assert data["ops_notified"] is False
            assert len(data["blocking_findings"]) >= 1

        app.dependency_overrides.clear()

    async def test_skip_compat_without_backend_source(self):
        responses = [VULN_SCAN, MUTATE_RESULT, {"notified": True}, CLEAN_SCAN]
        app.dependency_overrides[get_ace_client] = lambda: _mock_client(responses)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/rhg/submit", json=_submit_body(backend=False))
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] == "PATCHED"
            assert data["compatibility_verdict"] == "SKIPPED"
            assert data["ops_notified"] is True

        app.dependency_overrides.clear()

    async def test_allow_on_clean_scan(self):
        app.dependency_overrides[get_ace_client] = lambda: _mock_client([CLEAN_SCAN])

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/rhg/submit", json=_submit_body())
            data = resp.json()
            assert data["decision"] == "ALLOW"
            assert data["compatibility_verdict"] == "SKIPPED"
            assert data["ops_notified"] is False

        app.dependency_overrides.clear()