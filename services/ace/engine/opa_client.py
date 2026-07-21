from typing import Any
import httpx


class OPAClient:
    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.base = opa_url
        self._client = httpx.AsyncClient(timeout=10.0)

    async def evaluate(self, policy_path: str, input_data: dict) -> dict[str, Any]:
        url = f"{self.base}/v1/data/{policy_path.replace('.', '/')}"
        resp = await self._client.post(url, json={"input": input_data})
        resp.raise_for_status()
        return resp.json().get("result", {})

    async def evaluate_deny(self, policy_path: str, input_data: dict) -> list[dict]:
        result = await self.evaluate(policy_path, input_data)
        return result.get("deny", [])

    async def evaluate_patch(self, policy_path: str, input_data: dict) -> list[dict]:
        result = await self.evaluate(policy_path, input_data)
        return result.get("patch", [])

    async def health(self) -> bool:
        try:
            r = await self._client.get(f"{self.base}/health")
            return r.status_code == 200
        except Exception:
            return False
