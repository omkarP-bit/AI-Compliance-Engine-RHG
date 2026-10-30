from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class ActivityRecord:
    event_type: str
    scan_id: str | None = None
    repo: str | None = None
    branch: str | None = None
    environment: str | None = None
    overall_severity: str | None = None
    findings_count: int = 0
    mutations_applied: int = 0
    gate_decision: str | None = None
    triggered_by: str | None = None  # "cli" | "ci" | "agent"
    artifact_count: int = 0
    created_at: datetime | None = None
    extra: dict[str, Any] | None = None


@dataclass(slots=True)
class ApiKeyRecord:
    key_id: str
    key_hash: str
    org_id: str
    project_id: str | None = None
    repo_pattern: str | None = None
    scopes: list[str] | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(slots=True)
class OrgRecord:
    org_id: str
    name: str | None = None
    created_at: datetime | None = None


@dataclass(slots=True)
class ProjectRecord:
    project_id: str
    org_id: str
    repo: str | None = None
    created_at: datetime | None = None


class StorageBackend(ABC):
    @abstractmethod
    def record_activity(self, record: ActivityRecord) -> None: ...

    @abstractmethod
    def list_recent_activity(self, limit: int = 20) -> list[dict[str, Any]]: ...

    @abstractmethod
    def record_scan_summary(self, summary: dict[str, Any]) -> None: ...

    @abstractmethod
    def record_gate_decision(self, decision: dict[str, Any]) -> None: ...

    # Auth/org
    @abstractmethod
    def create_org(self, org: OrgRecord) -> None: ...

    @abstractmethod
    def create_project(self, project: ProjectRecord) -> None: ...

    @abstractmethod
    def create_api_key(self, key: ApiKeyRecord) -> None: ...

    @abstractmethod
    def get_api_key_by_hash(self, key_hash: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def list_api_keys(self, org_id: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def revoke_api_key(self, key_id: str) -> None: ...
