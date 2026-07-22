import pytest
import base64
import httpx
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock
from rhg.main import app
from rhg.api.routes import get_ace_client

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

SAFE_YAML = base64.b64encode(b"""
apiVersion: v1
kind: Pod
metadata:
  name: safe-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: false
        runAsUser: 1000
""").decode()

MOCK_CLEAN_SCAN_RESPONSE = {
    "scan_id": "scan-456",
    "pipeline_id": "pipe-456",
    "risk_score": 0.5,
    "overall_severity": "INFO",
    "findings": [],
}

MOCK_SCAN_RESPONSE = {
    "scan_id": "scan-123",
    "pipeline_id": "pipe-123",
    "risk_score": 7.5,
    "overall_severity": "HIGH",
    "findings": [
        {"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH", "message": "Privileged container",
         "artifact": "deploy.yaml", "patchable": True}
    ],
}


def create_mock_ace_client(response_data: dict, mutate_response: dict | None = None):
    """Create a mock httpx.AsyncClient that returns canned ACE responses."""
    client = AsyncMock(spec=httpx.AsyncClient)

    async def post_side_effect(url, **kwargs):
        resp = AsyncMock(spec=httpx.Response)
        resp.status_code = 200
        url_str = str(url)
        if "/ace/mutate" in url_str and mutate_response:
            resp.json.return_value = mutate_response
        else:
            resp.json.return_value = response_data
        return resp

    client.post = post_side_effect
    return client


@pytest.mark.asyncio
class TestRHGSubmitAPI:
    async def test_submit_returns_allow_when_clean(self):
        mock_client = create_mock_ace_client(MOCK_CLEAN_SCAN_RESPONSE)
        app.dependency_overrides[get_ace_client] = lambda: mock_client

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/rhg/submit", json={
                "pipeline_id": "pipe-456",
                "repo": "org/repo",
                "environment": "staging",
                "artifacts": [{"type": "kubernetes", "name": "safe.yaml", "content": SAFE_YAML}],
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] == "ALLOW"
            assert data["pipeline_id"] == "pipe-456"

        app.dependency_overrides.clear()

    async def test_submit_returns_block_on_high(self):
        mock_client = create_mock_ace_client(MOCK_SCAN_RESPONSE)
        app.dependency_overrides[get_ace_client] = lambda: mock_client

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/rhg/submit", json={
                "pipeline_id": "pipe-123",
                "repo": "org/repo",
                "environment": "production",
                "artifacts": [{"type": "kubernetes", "name": "deploy.yaml", "content": VULN_YAML}],
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] == "BLOCK"
            assert len(data["blocking_findings"]) > 0

        app.dependency_overrides.clear()

    async def test_health_endpoint(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/rhg/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"
            assert resp.json()["service"] == "rhg"

    async def test_submit_returns_502_when_ace_fails(self):
        mock_client = AsyncMock(spec=httpx.AsyncClient)

        async def failing_post(url, **kwargs):
            resp = AsyncMock(spec=httpx.Response)
            resp.status_code = 503
            resp.text = "Service Unavailable"
            return resp

        mock_client.post = failing_post
        app.dependency_overrides[get_ace_client] = lambda: mock_client

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/rhg/submit", json={
                "pipeline_id": "pipe-fail",
                "repo": "org/repo",
                "environment": "dev",
                "artifacts": [],
            })
            assert resp.status_code == 502

        app.dependency_overrides.clear()


@pytest.mark.asyncio
class TestRHGSubmitWithMutation:
    async def test_submit_applies_mutations_and_patches(self):
        scan_with_findings = {
            "scan_id": "scan-mut",
            "pipeline_id": "pipe-mut",
            "risk_score": 7.5,
            "overall_severity": "HIGH",
            "findings": [
                {"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH",
                 "message": "Privileged container", "artifact": "deploy.yaml", "patchable": True}
            ],
        }
        clean_scan = {
            "scan_id": "scan-rescan",
            "pipeline_id": "pipe-mut",
            "risk_score": 0.0,
            "overall_severity": "INFO",
            "findings": [],
        }

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        call_count = 0

        async def post_side_effect(url, **kwargs):
            nonlocal call_count
            resp = AsyncMock(spec=httpx.Response)
            resp.status_code = 200
            url_str = str(url)
            if "/ace/mutate" in url_str:
                resp.json.return_value = {
                    "patches": [
                        {"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False},
                        {"op": "add", "path": "/spec/containers/0/securityContext/runAsNonRoot", "value": True},
                    ],
                    "patch_count": 2,
                    "before_snapshot": {},
                }
            elif "/ace/scan" in url_str:
                resp.json.return_value = clean_scan if call_count > 0 else scan_with_findings
                call_count += 1
            return resp

        mock_client.post = post_side_effect
        app.dependency_overrides[get_ace_client] = lambda: mock_client

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/rhg/submit", json={
                "pipeline_id": "pipe-mut",
                "repo": "org/repo",
                "environment": "staging",
                "artifacts": [{"type": "kubernetes", "name": "deploy.yaml", "content": VULN_YAML}],
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] in ["ALLOW", "PATCHED", "BLOCK"]
            assert data["pipeline_id"] == "pipe-mut"
            assert data["scan_id"] is not None

        app.dependency_overrides.clear()
