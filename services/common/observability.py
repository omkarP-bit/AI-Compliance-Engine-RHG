"""Dashboard/report links used in alerts and API responses.

``DASHBOARD_URL`` is a *full* dashboard URL, not a base URL, so the same
variable can point either at the local Grafana dashboard or at the cloud
observability view (CloudWatch dashboard, Grafana Cloud, Amazon Managed
Grafana). Callers must not append paths to it.
"""

from __future__ import annotations

import os

DEFAULT_DASHBOARD_URL = "http://localhost:3000/d/ace-rhg-overview"


def get_report_url() -> str:
    """Return the configured dashboard URL, or the local Grafana dashboard."""
    return os.environ.get("DASHBOARD_URL") or DEFAULT_DASHBOARD_URL
