from typing import Any
from .opa_client import OPAClient


class RuleEngine:
    def __init__(self, opa_client: OPAClient):
        self.opa = opa_client
        self.policy_map: dict[str, str] = {
            "kubernetes": "ace/cis/kubernetes",
            "terraform": "ace/cis/terraform",
            "dockerfile": "ace/cis/docker",
            "helm": "ace/cis/kubernetes",
        }

    async def evaluate(self, artifact_type: str, input_data: dict) -> list[dict]:
        policy_path = self.policy_map.get(artifact_type)
        if not policy_path:
            return []
        return await self.opa.evaluate_deny(policy_path, input_data)
