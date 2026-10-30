from __future__ import annotations

import json
import os

from .base import MetricsClient


class CloudWatchMetrics(MetricsClient):
    """CloudWatch Embedded Metric Format (EMF) stub. No scrape endpoint needed."""

    def __init__(self) -> None:
        self.namespace = os.environ.get("CLOUDWATCH_NAMESPACE", "ACE-RHG")

    def increment(self, name: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
        self._emit(name, value, "Count", labels)

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        self._emit(name, value, "Seconds", labels)

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        self._emit(name, value, "None", labels)

    def _emit(self, name: str, value: float, unit: str, labels: dict[str, str] | None = None) -> None:
        # EMF output goes to stdout; AWS services will pick it up.
        dims = labels or {}
        payload = {
            "_aws": {
                "Timestamp": None,
                "CloudWatchMetrics": [
                    {
                        "Namespace": self.namespace,
                        "Dimensions": [list(dims.keys())] if dims else [],
                        "Metrics": [{"Name": name, "Unit": unit}],
                    }
                ],
            },
            **dims,
            name: value,
        }
        print(json.dumps(payload))
