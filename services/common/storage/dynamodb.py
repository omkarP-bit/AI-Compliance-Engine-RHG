from __future__ import annotations

import os
from typing import Any

from .base import ActivityRecord, StorageBackend


class DynamoDBStorage(StorageBackend):
    """Stub for DynamoDB (single-table). IAM role only. Metadata only."""

    def __init__(self) -> None:
        self.table_prefix = os.environ.get("DYNAMODB_TABLE_PREFIX", "ace-internal")
        self.endpoint_url = os.environ.get("DYNAMODB_ENDPOINT_URL")  # only for dynamodb-local
        self._client = None
        # PK = ACTIVITY#YYYY-MM-DD, SK = TS#epoch-ms#<id>

    def record_activity(self, record: ActivityRecord) -> None:
        return

    def list_recent_activity(self, limit: int = 20) -> list[dict[str, Any]]:
        return []

    def record_scan_summary(self, summary: dict[str, Any]) -> None:
        return

    def record_gate_decision(self, decision: dict[str, Any]) -> None:
        return

    def create_org(self, org) -> None:
        return

    def create_project(self, project) -> None:
        return

    def create_api_key(self, key) -> None:
        return

    def get_api_key_by_hash(self, key_hash: str):
        return None

    def list_api_keys(self, org_id: str | None = None):
        return []

    def revoke_api_key(self, key_id: str) -> None:
        return
