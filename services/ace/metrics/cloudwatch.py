"""CloudWatch Embedded Metric Format (EMF) exporter.

Lambda containers have no scrapeable port, so Prometheus cannot reach them.
Instead we print one EMF JSON document per metric sample to stdout; CloudWatch
Logs extracts the values into real CloudWatch metrics under
``CLOUDWATCH_NAMESPACE`` (default ``ACE-RHG``).

The metric names intentionally match the Prometheus metric names used by the
local Grafana dashboard so the same panels can be reproduced in Grafana Cloud /
Amazon Managed Grafana through the CloudWatch data source.
"""

from __future__ import annotations

import json
import os
import time

from .base import MetricsClient

#: Prometheus name -> CloudWatch metric name.
METRIC_NAMES = {
    "scans_total": "ace_scans_total",
    "findings_total": "ace_findings_total",
    "mutations_total": "ace_mutations_total",
    "gate_decisions_total": "rhg_gate_decisions_total",
    "scan_duration_seconds": "ace_scan_duration_seconds",
    "agent_duration_seconds": "ace_agent_duration_seconds",
    "active_scans": "ace_active_scans",
    "opa_health": "ace_opa_health",
    "compliance_score": "ace_compliance_score",
}

_UNIT_BY_NAME = {
    "scan_duration_seconds": "Seconds",
    "agent_duration_seconds": "Seconds",
}

_MAX_DIMENSION_VALUE = 250


def _running_in_lambda() -> bool:
    return bool(
        os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        or os.environ.get("AWS_EXECUTION_ENV")
    )


class CloudWatchMetrics(MetricsClient):
    """Emit EMF documents that CloudWatch Logs turns into custom metrics."""

    def __init__(self, namespace: str | None = None) -> None:
        self.namespace = namespace or os.environ.get(
            "CLOUDWATCH_NAMESPACE", "ACE-RHG"
        )
        default_enabled = "true" if _running_in_lambda() else "false"
        self.enabled = os.environ.get(
            "CLOUDWATCH_EMF_ENABLED", default_enabled
        ).strip().lower() not in {"0", "false", "no", "off"}

    def increment(self, name: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
        self._emit(name, value, "Count", labels)

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        self._emit(name, value, _UNIT_BY_NAME.get(name, "Seconds"), labels)

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        self._emit(name, value, "None", labels)

    def _emit(
        self,
        name: str,
        value: float,
        unit: str,
        labels: dict[str, str] | None = None,
    ) -> None:
        if not self.enabled:
            return

        metric_name = METRIC_NAMES.get(name, name)
        dimensions = self._clean_dimensions(labels)
        payload = {
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": self.namespace,
                        "Dimensions": [sorted(dimensions)] if dimensions else [],
                        "Metrics": [{"Name": metric_name, "Unit": unit}],
                    }
                ],
            },
            **dimensions,
            metric_name: value,
        }
        try:
            print(json.dumps(payload), flush=True)
        except (TypeError, ValueError):
            # Never let observability break a scan.
            return

    @staticmethod
    def _clean_dimensions(labels: dict[str, str] | None) -> dict[str, str]:
        dimensions: dict[str, str] = {}
        for key, value in (labels or {}).items():
            if value is None:
                continue
            cleaned = str(value)[:_MAX_DIMENSION_VALUE]
            if cleaned:
                dimensions[str(key)] = cleaned
        return dimensions
