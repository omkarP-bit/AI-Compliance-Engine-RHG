import pytest
import base64
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
from ace.main import app

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


@pytest.mark.asyncio
class TestScanAPI:
    async def test_scan_returns_200(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=True), \
                 patch("ace.api.routes.opa.evaluate_deny", new_callable=AsyncMock,
                       return_value=[{"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH"}]):
                resp = await client.post("/ace/scan", json={
                    "pipeline_id": "test-123",
                    "environment": "production",
                    "artifacts": [{"type": "kubernetes", "name": "deploy.yaml", "content": VULN_YAML}],
                })
                assert resp.status_code == 200

    async def test_scan_returns_findings_in_response(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=True), \
                 patch("ace.api.routes.opa.evaluate_deny", new_callable=AsyncMock,
                       return_value=[{"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH", "message": "Privileged"}]):
                resp = await client.post("/ace/scan", json={
                    "pipeline_id": "test-456",
                    "environment": "staging",
                    "artifacts": [{"type": "kubernetes", "name": "deploy.yaml", "content": VULN_YAML}],
                })
                data = resp.json()
                assert len(data["findings"]) >= 1
                assert data["overall_severity"] in ["HIGH", "CRITICAL", "MEDIUM", "LOW"]

    async def test_scan_returns_503_when_opa_down(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=False):
                resp = await client.post("/ace/scan", json={
                    "pipeline_id": "test-789",
                    "environment": "dev",
                    "artifacts": [],
                })
                assert resp.status_code == 503

    async def test_scan_skips_unsupported_artifacts(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=True), \
                 patch("ace.api.routes.opa.evaluate_deny", new_callable=AsyncMock, return_value=[]):
                resp = await client.post("/ace/scan", json={
                    "pipeline_id": "test-skip",
                    "environment": "dev",
                    "artifacts": [{"type": "text", "name": "readme.md", "content": base64.b64encode(b"hello").decode()}],
                })
                assert resp.status_code == 200
                assert len(resp.json()["findings"]) == 0

    async def test_health_endpoint(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"
