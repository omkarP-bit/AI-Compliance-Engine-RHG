import yaml
from .base import BaseParser, NormalizedArtifact


class KubernetesParser(BaseParser):
    SUPPORTED_KINDS = {"Deployment", "DaemonSet", "StatefulSet", "Pod", "CronJob", "Job"}

    def supports(self, filename: str) -> bool:
        return filename.endswith((".yaml", ".yml"))

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        raw = yaml.safe_load(content)
        kind = raw.get("kind", "Unknown")
        containers = self._extract_containers(raw)
        return NormalizedArtifact(
            artifact_type="kubernetes",
            name=name,
            raw=raw,
            metadata={
                "kind": kind,
                "namespace": raw.get("metadata", {}).get("namespace", "default"),
                "containers": containers,
                "service_account": raw.get("spec", {}).get("serviceAccountName"),
                "host_network": raw.get("spec", {}).get("hostNetwork", False),
                "host_pid": raw.get("spec", {}).get("hostPID", False),
            }
        )

    def _extract_containers(self, raw: dict) -> list[dict]:
        spec = raw.get("spec", {})
        template_spec = spec.get("template", {}).get("spec", spec)
        containers = template_spec.get("containers", [])
        init_containers = template_spec.get("initContainers", [])
        return containers + init_containers
