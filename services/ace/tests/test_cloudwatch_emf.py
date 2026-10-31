"""CloudWatch EMF exporter and metrics-routing tests.

In Lambda there is no scrape endpoint, so ``CloudWatchMetrics`` must print one
valid EMF document per sample and the ``track_*`` helpers must go through the
metrics factory instead of writing to Prometheus directly.
"""

import json

import pytest

from ace.metrics import prometheus
from ace.metrics.cloudwatch import METRIC_NAMES, CloudWatchMetrics


def _emitted(capsys) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]


class TestCloudWatchEmf:
    def test_increment_emits_valid_emf(self, capsys, monkeypatch):
        monkeypatch.setenv("CLOUDWATCH_EMF_ENABLED", "true")
        CloudWatchMetrics(namespace="ACE-RHG").increment(
            "scans_total", labels={"environment": "production", "outcome": "block"}
        )

        [payload] = _emitted(capsys)
        aws = payload["_aws"]
        assert isinstance(aws["Timestamp"], int)
        assert aws["Timestamp"] > 0

        [metric_directive] = aws["CloudWatchMetrics"]
        assert metric_directive["Namespace"] == "ACE-RHG"
        assert metric_directive["Dimensions"] == [["environment", "outcome"]]
        assert metric_directive["Metrics"] == [
            {"Name": "ace_scans_total", "Unit": "Count"}
        ]
        assert payload["environment"] == "production"
        assert payload["outcome"] == "block"
        assert payload["ace_scans_total"] == 1

    @pytest.mark.parametrize(
        ("name", "unit"),
        [
            ("findings_total", "Count"),
            ("gate_decisions_total", "Count"),
            ("scan_duration_seconds", "Seconds"),
            ("agent_duration_seconds", "Seconds"),
            ("opa_health", "None"),
            ("compliance_score", "None"),
            ("active_scans", "None"),
        ],
    )
    def test_metric_names_and_units(self, capsys, monkeypatch, name, unit):
        monkeypatch.setenv("CLOUDWATCH_EMF_ENABLED", "true")
        metrics = CloudWatchMetrics(namespace="ACE-RHG")
        if name.endswith("_seconds"):
            metrics.observe(name, 1.25)
        elif name in {"opa_health", "compliance_score", "active_scans"}:
            metrics.gauge(name, 1)
        else:
            metrics.increment(name)

        [payload] = _emitted(capsys)
        assert list(payload)[-1] == METRIC_NAMES[name]
        assert payload[METRIC_NAMES[name]] == (1.25 if name.endswith("_seconds") else 1)
        assert payload["_aws"]["CloudWatchMetrics"][0]["Metrics"][0]["Unit"] == unit

    def test_emf_disabled_emits_nothing(self, capsys, monkeypatch):
        monkeypatch.setenv("CLOUDWATCH_EMF_ENABLED", "false")
        CloudWatchMetrics(namespace="ACE-RHG").increment("scans_total")
        assert capsys.readouterr().out == ""

    def test_dimensionless_metric(self, capsys, monkeypatch):
        monkeypatch.setenv("CLOUDWATCH_EMF_ENABLED", "true")
        CloudWatchMetrics(namespace="ACE-RHG").gauge("opa_health", 1)

        [payload] = _emitted(capsys)
        assert payload["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == []
        assert payload["ace_opa_health"] == 1

    def test_blank_dimension_values_are_dropped(self, capsys, monkeypatch):
        monkeypatch.setenv("CLOUDWATCH_EMF_ENABLED", "true")
        CloudWatchMetrics(namespace="ACE-RHG").increment(
            "findings_total", labels={"severity": "HIGH", "rule_id": None}
        )

        [payload] = _emitted(capsys)
        assert payload["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [["severity"]]
        assert "rule_id" not in payload


class _Recorder:
    def __init__(self):
        self.calls: list[tuple] = []

    def increment(self, name, value=1, labels=None):
        self.calls.append(("increment", name, value, labels))

    def observe(self, name, value, labels=None):
        self.calls.append(("observe", name, value, labels))

    def gauge(self, name, value, labels=None):
        self.calls.append(("gauge", name, value, labels))


class TestTrackHelpersUseFactory:
    def setup_method(self):
        self.recorder = _Recorder()

    def _install(self, monkeypatch):
        monkeypatch.setattr(prometheus, "get_metrics_client", lambda: self.recorder)
        return self.recorder

    def test_track_scan(self, monkeypatch):
        recorder = self._install(monkeypatch)
        prometheus.track_scan(
            "production", "block", 1.5,
            [{"severity": "HIGH", "rule_id": "API-SEC-020"}],
        )
        assert recorder.calls == [
            ("increment", "scans_total", 1, {"environment": "production", "outcome": "block"}),
            ("observe", "scan_duration_seconds", 1.5, None),
            ("increment", "findings_total", 1, {"severity": "HIGH", "rule_id": "API-SEC-020"}),
        ]

    def test_track_gate_decision(self, monkeypatch):
        recorder = self._install(monkeypatch)
        prometheus.track_gate_decision("BLOCK", "production")
        assert recorder.calls == [
            ("increment", "gate_decisions_total", 1,
             {"decision": "BLOCK", "environment": "production"}),
        ]

    def test_track_mutation(self, monkeypatch):
        recorder = self._install(monkeypatch)
        prometheus.track_mutation("applied")
        assert recorder.calls == [
            ("increment", "mutations_total", 1, {"outcome": "applied"}),
        ]

    def test_track_agent_duration(self, monkeypatch):
        recorder = self._install(monkeypatch)
        prometheus.track_agent_duration("reasoner", 0.4)
        assert recorder.calls == [
            ("observe", "agent_duration_seconds", 0.4, {"agent_name": "reasoner"}),
        ]

    def test_track_opa_health(self, monkeypatch):
        recorder = self._install(monkeypatch)
        prometheus.track_opa_health(True)
        prometheus.track_opa_health(False)
        assert recorder.calls == [
            ("gauge", "opa_health", 1, None),
            ("gauge", "opa_health", 0, None),
        ]

    def test_track_compliance_score(self, monkeypatch):
        recorder = self._install(monkeypatch)
        prometheus.track_compliance_score("production", 7.5)
        assert recorder.calls == [
            ("gauge", "compliance_score", 7.5, {"environment": "production"}),
        ]
