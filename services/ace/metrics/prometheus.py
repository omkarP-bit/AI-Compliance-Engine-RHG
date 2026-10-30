from prometheus_client import Counter, Gauge, Histogram, start_http_server

from .base import MetricsClient

SCANS_TOTAL = Counter(
    "ace_scans_total", "Total scans performed", ["environment", "outcome"]
)
FINDINGS_TOTAL = Counter(
    "ace_findings_total", "Total findings emitted", ["severity", "rule_id"]
)
MUTATIONS_TOTAL = Counter(
    "ace_mutations_total", "Total auto-mutations applied", ["outcome"]
)
GATE_DECISIONS = Counter(
    "rhg_gate_decisions_total", "RHG gate decisions", ["decision", "environment"]
)

SCAN_DURATION = Histogram(
    "ace_scan_duration_seconds", "Scan latency", buckets=[0.1, 0.5, 1, 2, 5, 10]
)
AGENT_DURATION = Histogram(
    "ace_agent_duration_seconds", "Agent latency", ["agent_name"]
)

ACTIVE_SCANS = Gauge("ace_active_scans", "Currently running scans")
OPA_HEALTH = Gauge("ace_opa_health", "OPA engine health (1=up, 0=down)")
COMPLIANCE_SCORE = Gauge(
    "ace_compliance_score", "Current compliance score", ["environment"]
)


class PrometheusMetrics(MetricsClient):
    """Adapter over existing prometheus_client metrics for the factory."""

    def increment(self, name: str, value: int = 1, labels: dict[str, str] | None = None) -> None:
        labels = labels or {}
        if name == "scans_total":
            SCANS_TOTAL.labels(
                environment=labels.get("environment", "unknown"),
                outcome=labels.get("outcome", "unknown"),
            ).inc(value)
            return
        if name == "findings_total":
            FINDINGS_TOTAL.labels(
                severity=labels.get("severity", "UNKNOWN"),
                rule_id=labels.get("rule_id", "UNKNOWN"),
            ).inc(value)
            return
        if name == "mutations_total":
            MUTATIONS_TOTAL.labels(outcome=labels.get("outcome", "unknown")).inc(value)
            return
        if name == "gate_decisions_total":
            GATE_DECISIONS.labels(
                decision=labels.get("decision", "unknown"),
                environment=labels.get("environment", "unknown"),
            ).inc(value)
            return

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        labels = labels or {}
        if name == "scan_duration_seconds":
            SCAN_DURATION.observe(value)
            return
        if name == "agent_duration_seconds":
            AGENT_DURATION.labels(agent_name=labels.get("agent_name", "unknown")).observe(value)
            return

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        labels = labels or {}
        if name == "active_scans":
            ACTIVE_SCANS.set(value)
            return
        if name == "opa_health":
            OPA_HEALTH.set(value)
            return
        if name == "compliance_score":
            COMPLIANCE_SCORE.labels(environment=labels.get("environment", "unknown")).set(value)
            return


def track_scan(environment: str, outcome: str, duration: float, findings: list[dict]):
    SCANS_TOTAL.labels(environment=environment, outcome=outcome).inc()
    SCAN_DURATION.observe(duration)
    for f in findings:
        FINDINGS_TOTAL.labels(
            severity=f.get("severity") or "UNKNOWN",
            rule_id=f.get("rule_id") or "UNKNOWN",
        ).inc()


def track_gate_decision(decision: str, environment: str):
    GATE_DECISIONS.labels(decision=decision, environment=environment).inc()


def track_mutation(outcome: str):
    MUTATIONS_TOTAL.labels(outcome=outcome).inc()


def start_metrics_server(port: int = 9090):
    start_http_server(port)
