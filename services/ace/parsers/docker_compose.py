from typing import Any

import yaml

from .base import BaseParser, NormalizedArtifact

COMPOSE_FILENAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}


class DockerComposeParser(BaseParser):
    def supports(self, filename: str) -> bool:
        return filename in COMPOSE_FILENAMES or (
            filename.startswith("docker-compose.") and filename.endswith((".yml", ".yaml"))
        )

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        raw = yaml.safe_load(content) or {}
        services_raw = raw.get("services", {})
        services = [self._normalize_service(svc_name, svc) for svc_name, svc in services_raw.items()]
        return NormalizedArtifact(
            artifact_type="docker_compose",
            name=name,
            raw={
                "version": str(raw.get("version", "")),
                "services": services,
                "volumes": list((raw.get("volumes") or {}).keys()),
                "networks": list((raw.get("networks") or {}).keys()),
            },
            metadata={
                "service_names": list(services_raw.keys()),
                "service_count": len(services),
            },
        )

    @staticmethod
    def _normalize_service(name: str, svc: Any) -> dict:
        if not isinstance(svc, dict):
            svc = {}
        env = svc.get("environment", {})
        env_map: dict[str, str] = {}
        if isinstance(env, list):
            for item in env:
                if isinstance(item, str) and "=" in item:
                    k, v = item.split("=", 1)
                    env_map[k.strip()] = v.strip()
        elif isinstance(env, dict):
            env_map = {str(k): (str(v) if v is not None else "") for k, v in env.items()}
        return {
            "name": name,
            "image": str(svc.get("image", "")),
            "container_name": str(svc.get("container_name", "")),
            "ports": [str(p) for p in (svc.get("ports") or [])],
            "cap_add": [str(c) for c in (svc.get("cap_add") or [])],
            "privileged": bool(svc.get("privileged", False)),
            "user": str(svc.get("user", "") or ""),
            "command": str(svc.get("command", "") or ""),
            "volumes": [str(v) for v in (svc.get("volumes") or [])],
            "environment": env_map,
            "networks": [str(n) for n in (svc.get("networks") or [])],
        }