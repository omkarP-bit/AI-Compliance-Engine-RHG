"""``DASHBOARD_URL`` is a full URL and must be used verbatim.

This lets the same variable point at local Grafana, a CloudWatch dashboard, or
Grafana Cloud without the services appending ``/d/ace-rhg-overview`` to it.
"""

from common.observability import DEFAULT_DASHBOARD_URL, get_report_url


def test_default_is_local_grafana_dashboard(monkeypatch):
    monkeypatch.delenv("DASHBOARD_URL", raising=False)
    assert get_report_url() == DEFAULT_DASHBOARD_URL
    assert DEFAULT_DASHBOARD_URL.endswith("/d/ace-rhg-overview")


def test_cloudwatch_url_is_used_verbatim(monkeypatch):
    url = (
        "https://ap-south-1.console.aws.amazon.com/cloudwatch/home"
        "?region=ap-south-1#dashboards:name=ACE-RHG-Overview"
    )
    monkeypatch.setenv("DASHBOARD_URL", url)
    assert get_report_url() == url


def test_grafana_cloud_url_is_used_verbatim(monkeypatch):
    url = "https://acme.grafana.net/d/ace-rhg-cloudwatch"
    monkeypatch.setenv("DASHBOARD_URL", url)
    assert get_report_url() == url
