import re
import yaml
from .base import BaseParser, NormalizedArtifact


class HelmParser(BaseParser):
    def supports(self, filename: str) -> bool:
        return filename.endswith(".yaml") and "templates" in filename

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        raw = yaml.safe_load(content)
        helm_variables = self._extract_template_variables(content)
        return NormalizedArtifact(
            artifact_type="helm",
            name=name,
            raw=raw if isinstance(raw, dict) else {},
            metadata={
                "api_version": raw.get("apiVersion") if isinstance(raw, dict) else "",
                "kind": raw.get("kind") if isinstance(raw, dict) else "",
                "template_variables": helm_variables,
                "has_template_expressions": len(helm_variables) > 0,
            }
        )

    def _extract_template_variables(self, content: str) -> list[str]:
        return list(set(re.findall(r'\{\{\s*\.Values\.([\w.]+)\s*\}\}', content)))
