from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ace.engine.opa_client import OPAClient


@pytest.mark.asyncio
class TestOPAClient:
    async def test_health_returns_true_when_opa_up(self):
        client = OPAClient()
        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value.status_code = 200
            assert await client.health() is True

    async def test_health_returns_false_when_opa_down(self):
        client = OPAClient()
        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("Connection refused")
            assert await client.health() is False

    async def test_evaluate_deny_returns_findings(self):
        client = OPAClient()
        mock_result = {"result": {"deny": [{"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH"}]}}
        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = lambda: mock_result
            mock_post.return_value = mock_response
            findings = await client.evaluate_deny("ace.cis.kubernetes", {"spec": {}})
            assert len(findings) == 1
            assert findings[0]["rule_id"] == "CIS-K8S-5.2.1"

    async def test_evaluate_returns_empty_on_compliant_input(self):
        client = OPAClient()
        mock_result = {"result": {"deny": []}}
        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = lambda: mock_result
            mock_post.return_value = mock_response
            findings = await client.evaluate_deny("ace.cis.kubernetes", {})
            assert findings == []

    async def test_evaluate_patch_returns_patches(self):
        client = OPAClient()
        mock_result = {
            "result": {
                "patch": [
                    {"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False}
                ]
            }
        }
        with patch.object(client._client, "post", new_callable=AsyncMock) as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json = lambda: mock_result
            mock_post.return_value = mock_response
            patches = await client.evaluate_patch("ace.cis.kubernetes", {"spec": {"containers": [{}]}})
            assert len(patches) == 1
            assert patches[0]["op"] == "replace"

    async def test_health_handles_connection_errors(self):
        client = OPAClient()
        with patch.object(client._client, "get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("Failed to connect")
            assert await client.health() is False
