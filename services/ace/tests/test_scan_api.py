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


class TestMutateAPI:
    @pytest.mark.asyncio
    async def test_mutate_returns_patches(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.evaluate_patch", new_callable=AsyncMock,
                       return_value=[{"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False}]):
                resp = await client.post("/ace/mutate", json={
                    "artifact_type": "kubernetes",
                    "artifact": {"spec": {"containers": [{"securityContext": {"privileged": True}}]}},
                    "finding_ids": ["finding-1"],
                })
                assert resp.status_code == 200
                data = resp.json()
                assert data["patch_count"] == 1
                assert len(data["patches"]) == 1
                assert data["patches"][0]["op"] == "replace"

    @pytest.mark.asyncio
    async def test_mutate_returns_before_snapshot(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.evaluate_patch", new_callable=AsyncMock, return_value=[]):
                resp = await client.post("/ace/mutate", json={
                    "artifact_type": "kubernetes",
                    "artifact": {"spec": {"containers": [{"name": "app"}]}},
                    "finding_ids": [],
                })
                assert resp.status_code == 200
                data = resp.json()
                assert "before_snapshot" in data
                assert data["before_snapshot"]["spec"]["containers"][0]["name"] == "app"

    @pytest.mark.asyncio
    async def test_mutate_returns_empty_patches_for_clean_artifact(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.evaluate_patch", new_callable=AsyncMock, return_value=[]):
                resp = await client.post("/ace/mutate", json={
                    "artifact_type": "kubernetes",
                    "artifact": {"spec": {"containers": [{"securityContext": {"privileged": False}}]}},
                    "finding_ids": [],
                })
                assert resp.status_code == 200
                assert resp.json()["patch_count"] == 0


class TestScanAndMutateAPI:
    @pytest.mark.asyncio
    async def test_scan_and_mutate_returns_findings_and_patches(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=True), \
                 patch("ace.api.routes.opa.evaluate_deny", new_callable=AsyncMock,
                       return_value=[{"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH", "message": "Privileged"}]):
                with patch("ace.api.routes.opa.evaluate_patch", new_callable=AsyncMock,
                           return_value=[{"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False}]):
                    resp = await client.post("/ace/scan-and-mutate", json={
                        "pipeline_id": "test-sam",
                        "environment": "staging",
                        "artifacts": [{"type": "kubernetes", "name": "deploy.yaml", "content": VULN_YAML}],
                    })
                    assert resp.status_code == 200
                    data = resp.json()
                    assert len(data["findings"]) >= 1
                    assert data["patch_count"] >= 1
                    assert len(data["mutations_applied"]) >= 1

    @pytest.mark.asyncio
    async def test_scan_and_mutate_returns_503_when_opa_down(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=False):
                resp = await client.post("/ace/scan-and-mutate", json={
                    "pipeline_id": "test-sam-down",
                    "environment": "dev",
                    "artifacts": [],
                })
                assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_scan_and_mutate_skips_unsupported_artifacts(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=True), \
                 patch("ace.api.routes.opa.evaluate_deny", new_callable=AsyncMock, return_value=[]), \
                 patch("ace.api.routes.opa.evaluate_patch", new_callable=AsyncMock, return_value=[]):
                resp = await client.post("/ace/scan-and-mutate", json={
                    "pipeline_id": "test-sam-skip",
                    "environment": "dev",
                    "artifacts": [{"type": "text", "name": "readme.md",
                                   "content": base64.b64encode(b"hello").decode()}],
                })
                assert resp.status_code == 200
                assert resp.json()["patch_count"] == 0

    @pytest.mark.asyncio
    async def test_scan_and_mutate_annotates_patches_with_artifact_name(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            with patch("ace.api.routes.opa.health", new_callable=AsyncMock, return_value=True), \
                 patch("ace.api.routes.opa.evaluate_deny", new_callable=AsyncMock, return_value=[]), \
                 patch("ace.api.routes.opa.evaluate_patch", new_callable=AsyncMock,
                       return_value=[{"op": "replace", "path": "/x", "value": False}]):
                resp = await client.post("/ace/scan-and-mutate", json={
                    "pipeline_id": "test-sam-ann",
                    "environment": "dev",
                    "artifacts": [
                        {"type": "kubernetes", "name": "a.yaml",
                         "content": base64.b64encode(b"kind: Pod\nspec: {}").decode()},
                        {"type": "kubernetes", "name": "b.yaml",
                         "content": base64.b64encode(b"kind: Pod\nspec: {}").decode()},
                    ],
                })
                assert resp.status_code == 200
                data = resp.json()
                assert data["patch_count"] > 0
                for p in data.get("mutations_applied", []):
                    assert p is not None
