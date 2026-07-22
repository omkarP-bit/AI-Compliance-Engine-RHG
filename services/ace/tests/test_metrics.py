import pytest
from prometheus_client import REGISTRY

from ace.metrics.prometheus import (
    track_scan,
    track_gate_decision,
    track_mutation,
    COMPLIANCE_SCORE,
    OPA_HEALTH,
    ACTIVE_SCANS,
)


class TestMetricsExporter:
    def _sample_value(self, metric_name, labels=None):
        labels = labels or {}
        for metric in REGISTRY.collect():
            for sample in metric.samples:
                if sample.name == metric_name and sample.labels == labels:
                    return sample.value
        return None

    def test_track_scan_increments_counter(self):
        before = self._sample_value(
            "ace_scans_total", {"environment": "production", "outcome": "allow"}
        ) or 0
        track_scan("production", "allow", 1.5, [])
        after = self._sample_value(
            "ace_scans_total", {"environment": "production", "outcome": "allow"}
        )
        assert after == before + 1

    def test_track_scan_records_findings(self):
        before = self._sample_value(
            "ace_findings_total", {"severity": "HIGH", "rule_id": "CIS-K8S-5.2.1"}
        ) or 0
        findings = [{"severity": "HIGH", "rule_id": "CIS-K8S-5.2.1"}]
        track_scan("staging", "block", 2.0, findings)
        after = self._sample_value(
            "ace_findings_total", {"severity": "HIGH", "rule_id": "CIS-K8S-5.2.1"}
        )
        assert after == before + 1

    def test_track_scan_records_duration_histogram(self):
        before_count = self._sample_value("ace_scan_duration_seconds_count") or 0
        track_scan("dev", "allow", 0.3, [])
        after_count = self._sample_value("ace_scan_duration_seconds_count")
        assert after_count == before_count + 1

    def test_track_gate_decision_increments_counter(self):
        before = self._sample_value(
            "rhg_gate_decisions_total",
            {"decision": "BLOCK", "environment": "production"},
        ) or 0
        track_gate_decision("BLOCK", "production")
        after = self._sample_value(
            "rhg_gate_decisions_total",
            {"decision": "BLOCK", "environment": "production"},
        )
        assert after == before + 1

    def test_track_mutation_increments_counter(self):
        before = self._sample_value(
            "ace_mutations_total", {"outcome": "success"}
        ) or 0
        track_mutation("success")
        after = self._sample_value(
            "ace_mutations_total", {"outcome": "success"}
        )
        assert after == before + 1

    def test_track_scan_handles_unknown_severity(self):
        before = self._sample_value(
            "ace_findings_total", {"severity": "UNKNOWN", "rule_id": "UNKNOWN"}
        ) or 0
        track_scan("dev", "allow", 0.1, [{"severity": None}])
        after = self._sample_value(
            "ace_findings_total", {"severity": "UNKNOWN", "rule_id": "UNKNOWN"}
        )
        assert after == before + 1

    def test_compliance_score_gauge(self):
        COMPLIANCE_SCORE.labels(environment="production").set(8.5)
        value = self._sample_value("ace_compliance_score", {"environment": "production"})
        assert value == 8.5

    def test_opa_health_gauge(self):
        OPA_HEALTH.set(1)
        value = self._sample_value("ace_opa_health")
        assert value == 1
        OPA_HEALTH.set(0)
        value = self._sample_value("ace_opa_health")
        assert value == 0

    def test_active_scans_gauge(self):
        ACTIVE_SCANS.inc()
        ACTIVE_SCANS.inc()
        value = self._sample_value("ace_active_scans")
        assert value == 2
        ACTIVE_SCANS.dec()
        value = self._sample_value("ace_active_scans")
        assert value == 1
