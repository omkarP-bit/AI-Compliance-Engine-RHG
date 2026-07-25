import re
from pathlib import Path
from typing import Any

import yaml

from .base import BaseParser, NormalizedArtifact


class GitHubActionsParser(BaseParser):
    SHA_RE = re.compile(r"^[0-9a-f]{40}$")

    def supports(self, filename: str) -> bool:
        path = Path(filename)
        parts = path.parts
        return (
            filename.endswith((".yml", ".yaml"))
            and (
                ".github/workflows" in parts
                or ".github/workflows" in filename
                or (len(parts) >= 2 and parts[0] == "workflows")
            )
        )

    @staticmethod
    def _normalize_keys(d: Any) -> Any:
        if isinstance(d, dict):
            result = {}
            for k, v in d.items():
                key = str(k)
                if key == "True":
                    key = "on"
                result[key] = GitHubActionsParser._normalize_keys(v)
            return result
        if isinstance(d, list):
            return [GitHubActionsParser._normalize_keys(i) for i in d]
        return d

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        raw = self._normalize_keys(yaml.safe_load(content) or {})
        on_value = raw.get("on", {})
        triggers = list(on_value.keys()) if isinstance(on_value, dict) else ([on_value] if isinstance(on_value, str) else [])
        return NormalizedArtifact(
            artifact_type="github_actions",
            name=name,
            raw=raw,
            metadata={
                "triggers": triggers,
                "top_level_perms": raw.get("permissions"),
                "jobs": self._extract_jobs(raw),
                "uses_actions": self._extract_action_refs(raw),
                "env_keys": list((raw.get("env") or {}).keys()),
                "has_pull_request_target": "pull_request_target" in on_value if isinstance(on_value, dict) else False,
            }
        )

    def _extract_jobs(self, raw: dict) -> list[dict]:
        jobs = []
        for job_id, job in (raw.get("jobs") or {}).items():
            steps = job.get("steps") or []
            run_steps = [s.get("run", "") for s in steps if s.get("run")]
            jobs.append({
                "id": job_id,
                "runs_on": job.get("runs-on", ""),
                "permissions": job.get("permissions"),
                "env_keys": list((job.get("env") or {}).keys()),
                "run_steps": run_steps,
                "self_hosted": self._is_self_hosted(job.get("runs-on", "")),
            })
        return jobs

    def _extract_action_refs(self, raw: dict) -> list[dict]:
        refs = []
        for job in (raw.get("jobs") or {}).values():
            for step in (job.get("steps") or []):
                uses = step.get("uses", "")
                if uses:
                    parts_ = uses.split("@", 1)
                    pin = parts_[1] if len(parts_) == 2 else ""
                    refs.append({
                        "action": parts_[0],
                        "pin": pin,
                        "sha_pinned": bool(self.SHA_RE.match(pin)),
                    })
        return refs

    @staticmethod
    def _is_self_hosted(runs_on) -> bool:
        if isinstance(runs_on, list):
            return "self-hosted" in runs_on
        return "self-hosted" in str(runs_on)
