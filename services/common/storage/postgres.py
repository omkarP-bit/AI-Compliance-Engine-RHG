from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

from .base import ActivityRecord, ApiKeyRecord, OrgRecord, ProjectRecord, StorageBackend


class PostgresStorage(StorageBackend):
    """Local Postgres adapter (file-backed JSON store for dev until SQL wired)."""

    def __init__(self) -> None:
        self._path = os.environ.get("ACE_LOCAL_STORE", os.path.expanduser("~/.config/ace/local_store.json"))
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {"orgs": {}, "projects": {}, "keys": [], "activity": []}
        else:
            self._data = {"orgs": {}, "projects": {}, "keys": [], "activity": []}

    def _save(self):
        try:
            with open(self._path, "w") as f:
                json.dump(self._data, f, indent=2, default=str)
        except Exception:
            pass

    def record_activity(self, record: ActivityRecord) -> None:
        item = {
            "event_type": record.event_type,
            "scan_id": record.scan_id,
            "repo": record.repo,
            "branch": record.branch,
            "environment": record.environment,
            "overall_severity": record.overall_severity,
            "findings_count": record.findings_count,
            "mutations_applied": record.mutations_applied,
            "gate_decision": record.gate_decision,
            "triggered_by": record.triggered_by,
            "artifact_count": record.artifact_count,
            "created_at": record.created_at.isoformat() if record.created_at else datetime.utcnow().isoformat(),
            "extra": record.extra or {},
        }
        self._data["activity"].insert(0, item)
        self._data["activity"] = self._data["activity"][:500]
        self._save()

    def list_recent_activity(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._data.get("activity", [])[:limit]

    def record_scan_summary(self, summary: dict[str, Any]) -> None:
        return

    def record_gate_decision(self, decision: dict[str, Any]) -> None:
        return

    def create_org(self, org: OrgRecord) -> None:
        self._data["orgs"][org.org_id] = {
            "org_id": org.org_id,
            "name": org.name,
            "created_at": org.created_at.isoformat() if org.created_at else datetime.utcnow().isoformat(),
        }
        self._save()

    def create_project(self, project: ProjectRecord) -> None:
        key = f"{project.org_id}:{project.project_id}"
        self._data["projects"][key] = {
            "project_id": project.project_id,
            "org_id": project.org_id,
            "repo": project.repo,
            "created_at": project.created_at.isoformat() if project.created_at else datetime.utcnow().isoformat(),
        }
        self._save()

    def create_api_key(self, key: ApiKeyRecord) -> None:
        self._data["keys"].append(
            {
                "key_id": key.key_id,
                "key_hash": key.key_hash,
                "org_id": key.org_id,
                "project_id": key.project_id,
                "repo_pattern": key.repo_pattern,
                "scopes": key.scopes or ["scan", "submit"],
                "created_at": key.created_at.isoformat() if key.created_at else datetime.utcnow().isoformat(),
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "revoked_at": None,
            }
        )
        self._save()

    def get_api_key_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        for k in self._data.get("keys", []):
            if k["key_hash"] == key_hash and not k.get("revoked_at"):
                return k
        return None

    def list_api_keys(self, org_id: str | None = None) -> list[dict[str, Any]]:
        keys = self._data.get("keys", [])
        if org_id:
            keys = [k for k in keys if k.get("org_id") == org_id]
        return keys

    def revoke_api_key(self, key_id: str) -> None:
        for k in self._data.get("keys", []):
            if k["key_id"] == key_id:
                k["revoked_at"] = datetime.utcnow().isoformat()
        self._save()
