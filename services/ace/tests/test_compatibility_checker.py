import pytest
from httpx import ASGITransport, AsyncClient

from ace.main import app

BASE_BACKEND_SCAN = {
    "language": "python",
    "port_bindings": [8000],
    "env_vars_used": ["DATABASE_URL", "REDIS_URL"],
    "routes": ["/health", "/ace/scan"],
    "frameworks": ["fastapi"],
}


@pytest.mark.asyncio
class TestCompatibilityChecker:
    async def _check(self, mutations, backend=None) -> dict:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/ace/compatibility-check",
                json={
                    "pipeline_id": "test",
                    "patched_artifact": {
                        "type": "kubernetes",
                        "name": "deploy.yaml",
                        "content": "",
                    },
                    "backend_scan": backend if backend is not None else BASE_BACKEND_SCAN,
                    "mutations_applied": mutations,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def test_compatible_mutation_passes(self):
        result = await self._check(
            [
                {
                    "op": "replace",
                    "path": "/spec/containers/0/securityContext/privileged",
                    "value": False,
                }
            ]
        )
        assert result["compatible"] is True
        assert result["verdict"] == "COMPATIBLE"
        assert result["mismatches"] == []

    async def test_port_mismatch_is_incompatible(self):
        result = await self._check(
            [
                {
                    "op": "replace",
                    "path": "/spec/containers/0/ports/0/containerPort",
                    "value": 8080,
                }
            ]
        )
        assert result["compatible"] is False
        assert result["verdict"] == "INCOMPATIBLE"
        assert any("8080" in m["detail"] for m in result["mismatches"])

    async def test_port_matching_backend_is_compatible(self):
        result = await self._check(
            [
                {
                    "op": "replace",
                    "path": "/spec/containers/0/ports/0/containerPort",
                    "value": 8000,
                }
            ]
        )
        assert result["compatible"] is True

    async def test_cpu_limit_change_is_compatible(self):
        result = await self._check(
            [
                {
                    "op": "replace",
                    "path": "/spec/containers/0/resources/limits/cpu",
                    "value": "100m",
                }
            ]
        )
        assert result["compatible"] is True

    async def test_env_var_removal_when_backend_uses_it_is_incompatible(self):
        result = await self._check(
            [{"op": "remove", "path": "/spec/containers/0/env/DATABASE_URL/value"}]
        )
        assert result["compatible"] is False
        assert any("DATABASE_URL" in m["detail"] for m in result["mismatches"])

    async def test_no_mutations_returns_compatible(self):
        result = await self._check([])
        assert result["compatible"] is True
        assert result["verdict"] == "COMPATIBLE"

    async def test_no_backend_scan_skips_checks(self):
        result = await self._check(
            [
                {
                    "op": "replace",
                    "path": "/spec/containers/0/ports/0/containerPort",
                    "value": 9090,
                }
            ],
            backend={},
        )
        assert result["verdict"] == "COMPATIBLE"

    async def test_probe_path_mismatch_is_needs_review(self):
        result = await self._check(
            [
                {
                    "op": "replace",
                    "path": "/spec/containers/0/readinessProbe/httpGet/path",
                    "value": "/ready",
                }
            ]
        )
        assert result["verdict"] == "NEEDS_REVIEW"
        assert result["compatible"] is False