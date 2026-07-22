from typing import Any
import httpx


OPA_V1_SET_KEYS = {"allow", "deny", "patch"}


def _unwrap_set(data: dict) -> list:
    if isinstance(data, dict) and all(isinstance(k, str) for k in data):
        items = []
        for k in data:
            try:
                import json
                items.append(json.loads(k))
            except (json.JSONDecodeError, TypeError):
                items.append(k)
        return items
    return data if isinstance(data, list) else []


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
        raw = result.get("deny", [])
        return _unwrap_set(raw) if isinstance(raw, dict) else raw

    async def evaluate_patch(self, policy_path: str, input_data: dict) -> list[dict]:
        result = await self.evaluate(policy_path, input_data)
        raw = result.get("patch", [])
        return _unwrap_set(raw) if isinstance(raw, dict) else raw

    async def health(self) -> bool:
        try:
            r = await self._client.get(f"{self.base}/health")
            return r.status_code == 200
        except Exception:
            return False
