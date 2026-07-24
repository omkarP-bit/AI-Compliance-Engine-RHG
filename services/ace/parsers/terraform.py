import json

from .base import BaseParser, NormalizedArtifact


class TerraformParser(BaseParser):
    def supports(self, filename: str) -> bool:
        return filename.endswith((".tf", ".tf.json", "tfplan.json"))

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        raw = json.loads(content)
        resources = self._extract_resources(raw)
        return NormalizedArtifact(
            artifact_type="terraform",
            name=name,
            raw=raw,
            metadata={
                "resources": resources,
                "resource_types": list({r["type"] for r in resources}),
                "provider": raw.get("configuration", {}).get("provider_config", {}),
            }
        )

    def _extract_resources(self, plan: dict) -> list[dict]:
        changes = plan.get("resource_changes", [])
        return [
            {
                "address": c["address"],
                "type": c["type"],
                "change_action": c["change"]["actions"],
                "values": c["change"].get("after", {}),
            }
            for c in changes
            if c.get("change", {}).get("actions") != ["no-op"]
        ]
