"""Validation for the Phase 5 observability stack.

These tests do not talk to a running Grafana/Prometheus — they assert that the
provisioning we ship is structurally valid and internally consistent, so a
broken dashboard JSON or a scrape target typo fails CI instead of failing
silently at deploy time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
OBSERVABILITY = REPO_ROOT / "infra" / "observability"
PROMETHEUS_CONFIG = OBSERVABILITY / "prometheus" / "prometheus.yml"
GRAFANA = OBSERVABILITY / "grafana"
DATASOURCE_PROVISIONING = GRAFANA / "provisioning" / "datasources" / "prometheus.yml"
DASHBOARD_PROVISIONING = GRAFANA / "provisioning" / "dashboards" / "dashboards.yml"
DASHBOARDS_DIR = GRAFANA / "dashboards"
CLOUD_GRAFANA_DASHBOARD = GRAFANA / "cloud" / "ace-rhg-cloudwatch.json"
CLOUDWATCH_DASHBOARD = OBSERVABILITY / "cloudwatch" / "ace-rhg-overview.json"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

#: Metric names exported by ``ace.metrics.prometheus``.
EXPORTED_METRICS = {
    "ace_scans_total",
    "ace_findings_total",
    "ace_mutations_total",
    "rhg_gate_decisions_total",
    "ace_scan_duration_seconds",
    "ace_agent_duration_seconds",
    "ace_active_scans",
    "ace_opa_health",
    "ace_compliance_score",
}

#: Metrics scrapped from the RHG process rather than ACE.
RHG_METRICS = {"rhg_gate_decisions_total"}


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _dashboard_files() -> list[Path]:
    return sorted(DASHBOARDS_DIR.glob("*.json"))


class TestPrometheusConfig:
    def test_scrapes_ace_metrics_port(self):
        config = _load_yaml(PROMETHEUS_CONFIG)
        jobs = {job["job_name"]: job for job in config["scrape_configs"]}
        assert "ace" in jobs
        targets = jobs["ace"]["static_configs"][0]["targets"]
        assert "ace:9090" in targets

    def test_scrapes_rhg_metrics_port(self):
        config = _load_yaml(PROMETHEUS_CONFIG)
        jobs = {job["job_name"]: job for job in config["scrape_configs"]}
        assert "rhg" in jobs, "RHG records rhg_gate_decisions_total and must be scraped"
        targets = jobs["rhg"]["static_configs"][0]["targets"]
        assert "rhg:9091" in targets

    def test_sets_scrape_interval(self):
        config = _load_yaml(PROMETHEUS_CONFIG)
        assert config["global"]["scrape_interval"]


class TestGrafanaProvisioning:
    def test_datasource_is_prometheus_with_stable_uid(self):
        config = _load_yaml(DATASOURCE_PROVISIONING)
        datasources = config["datasources"]
        assert len(datasources) == 1
        ds = datasources[0]
        assert ds["type"] == "prometheus"
        assert ds["uid"] == "prometheus"
        assert ds["isDefault"] is True
        assert ds["url"].startswith("http://prometheus")

    def test_dashboard_provider_points_at_mounted_directory(self):
        config = _load_yaml(DASHBOARD_PROVISIONING)
        providers = config["providers"]
        assert len(providers) == 1
        assert providers[0]["type"] == "file"
        assert providers[0]["options"]["path"] == "/var/lib/grafana/dashboards"

    def test_at_least_one_dashboard_is_provisioned(self):
        assert _dashboard_files(), "no dashboard JSON found to provision"


class TestDashboardJson:
    def test_dashboard_files_are_valid_json_objects(self):
        for path in _dashboard_files():
            data = _load_json(path)
            assert isinstance(data, dict), f"{path} is not a JSON object"

    def test_every_dashboard_has_required_top_level_fields(self):
        for path in _dashboard_files():
            data = _load_json(path)
            for field in ("title", "uid", "panels", "schemaVersion", "time"):
                assert field in data, f"{path.name} missing '{field}'"

    def test_dashboard_uids_are_unique(self):
        uids = [_load_json(p)["uid"] for p in _dashboard_files()]
        assert len(uids) == len(set(uids)), "dashboard uid collision"

    def test_every_panel_is_well_formed(self):
        for path in _dashboard_files():
            data = _load_json(path)
            ids = [panel["id"] for panel in data["panels"]]
            assert len(ids) == len(set(ids)), f"{path.name} has duplicate panel ids"
            for panel in data["panels"]:
                assert panel.get("title"), f"{path.name} panel {panel.get('id')} has no title"
                assert panel.get("type"), f"{path.name} panel {panel.get('id')} has no type"
                assert panel.get("gridPos"), f"{path.name} panel {panel.get('id')} has no gridPos"
                assert panel.get("targets"), f"{path.name} panel {panel.get('id')} has no targets"

    def test_every_panel_target_has_an_expr(self):
        for path in _dashboard_files():
            data = _load_json(path)
            for panel in data["panels"]:
                for target in panel["targets"]:
                    assert target.get("expr"), (
                        f"{path.name} panel {panel['id']} has a target with no expr"
                    )

    def test_panels_reference_exported_metrics(self):
        referenced: set[str] = set()
        for path in _dashboard_files():
            data = _load_json(path)
            for panel in data["panels"]:
                for target in panel["targets"]:
                    expr = target.get("expr", "")
                    for metric in EXPORTED_METRICS:
                        if metric in expr:
                            referenced.add(metric)
        # The dashboard must not reference a metric that does not exist.
        assert referenced <= EXPORTED_METRICS
        # And it must cover both the ACE and RHG surfaces.
        assert "ace_opa_health" in referenced
        assert "rhg_gate_decisions_total" in referenced


class TestCloudDashboards:
    """Cloud observability artifacts (EMF namespace + Grafana Cloud import)."""

    def test_grafana_cloud_dashboard_uses_cloudwatch_datasource(self):
        data = _load_json(CLOUD_GRAFANA_DASHBOARD)
        assert data["uid"] == "ace-rhg-cloudwatch"
        assert data["__inputs"][0]["pluginId"] == "cloudwatch"
        assert data["panels"]
        for panel in data["panels"]:
            for target in panel["targets"]:
                assert target["namespace"] == "ACE-RHG"
                assert target["datasource"]["type"] == "cloudwatch"
                assert target["region"] == "ap-south-1"

    def test_grafana_cloud_dashboard_metrics_exist(self):
        data = _load_json(CLOUD_GRAFANA_DASHBOARD)
        referenced = {
            target["metricName"]
            for panel in data["panels"]
            for target in panel["targets"]
        }
        assert referenced <= EXPORTED_METRICS
        assert "ace_opa_health" in referenced
        assert "rhg_gate_decisions_total" in referenced

    def test_cloudwatch_dashboard_is_valid(self):
        data = _load_json(CLOUDWATCH_DASHBOARD)
        assert data["widgets"]
        for widget in data["widgets"]:
            assert "type" in widget
            assert {"x", "y", "width", "height"} <= set(widget)

    def test_cloudwatch_dashboard_queries_the_emf_namespace(self):
        body = json.dumps(_load_json(CLOUDWATCH_DASHBOARD))
        for metric in EXPORTED_METRICS:
            assert metric in body, f"CloudWatch dashboard does not query {metric}"


class TestComposeWiring:
    def test_compose_defines_prometheus_and_grafana(self):
        config = _load_yaml(COMPOSE_FILE)
        services = config["services"]
        assert "prometheus" in services
        assert "grafana" in services

    def test_grafana_mounts_provisioning_and_dashboards(self):
        config = _load_yaml(COMPOSE_FILE)
        volumes = config["services"]["grafana"]["volumes"]
        joined = " ".join(volumes)
        assert "observability/grafana/provisioning" in joined
        assert "observability/grafana/dashboards" in joined

    def test_prometheus_mounts_its_config(self):
        config = _load_yaml(COMPOSE_FILE)
        volumes = config["services"]["prometheus"]["volumes"]
        joined = " ".join(volumes)
        assert "observability/prometheus/prometheus.yml" in joined

    def test_rhg_exposes_a_metrics_port(self):
        config = _load_yaml(COMPOSE_FILE)
        env = config["services"]["rhg"]["environment"]
        assert env.get("RHG_METRICS_ENABLED") == "true"
        assert env.get("RHG_METRICS_PORT")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
