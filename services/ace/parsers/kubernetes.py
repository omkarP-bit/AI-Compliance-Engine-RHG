from typing import ClassVar

import yaml

from .base import BaseParser, NormalizedArtifact


class KubernetesParser(BaseParser):
    SUPPORTED_KINDS: ClassVar[set[str]] = {"Deployment", "DaemonSet", "StatefulSet", "Pod", "CronJob", "Job"}

    def supports(self, filename: str) -> bool:
        return filename.endswith((".yaml", ".yml"))

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        docs = list(yaml.safe_load_all(content))
        raw = docs[0] if docs else {}
        kind = raw.get("kind", "Unknown")
        containers = self._extract_containers(raw)
        opa_input = self._normalize_for_opa(raw)
        return NormalizedArtifact(
            artifact_type="kubernetes",
            name=name,
            raw=opa_input,
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

    @staticmethod
    def _normalize_for_opa(raw: dict) -> dict:
        kind = raw.get("kind", "")
        spec = dict(raw.get("spec", {}))
        if kind in ("Deployment", "DaemonSet", "StatefulSet", "CronJob", "Job"):
            template_spec = spec.get("template", {}).get("spec", {})
            spec["containers"] = template_spec.get("containers", [])
            spec["initContainers"] = template_spec.get("initContainers", [])
            spec["hostNetwork"] = template_spec.get("hostNetwork", False)
            spec["hostPID"] = template_spec.get("hostPID", False)
        return {"apiVersion": raw.get("apiVersion"), "kind": kind, "metadata": raw.get("metadata", {}), "spec": spec}
