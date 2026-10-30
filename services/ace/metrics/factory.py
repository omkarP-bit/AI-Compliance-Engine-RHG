from __future__ import annotations

import os

from .base import MetricsClient

_cached: MetricsClient | None = None


def get_metrics_client() -> MetricsClient:
    global _cached
    if _cached is not None:
        return _cached

    backend = os.environ.get("METRICS_BACKEND", "").strip().lower()

    if not backend:
        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("AWS_EXECUTION_ENV"):
            backend = "cloudwatch"
        else:
            backend = "prometheus"

    if backend == "cloudwatch":
        from .cloudwatch import CloudWatchMetrics

        _cached = CloudWatchMetrics()
        return _cached

    if backend == "prometheus":
        from .prometheus import PrometheusMetrics

        _cached = PrometheusMetrics()
        return _cached

    from .prometheus import PrometheusMetrics

    _cached = PrometheusMetrics()
    return _cached
