from ace.scoring.risk_scorer import score_findings, Severity

CRITICAL_FINDING = {"rule_id": "CIS-K8S-5.2.4", "severity": "CRITICAL", "message": "Host network"}
HIGH_FINDING = {"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH", "message": "Privileged container"}
MEDIUM_FINDING = {"rule_id": "CIS-K8S-5.4.1", "severity": "MEDIUM", "message": "No CPU limit"}


class TestRiskScorer:
    def test_empty_findings_returns_zero_score(self):
        result = score_findings([])
        assert result.score == 0.0
        assert result.severity == Severity.INFO

    def test_critical_finding_dominates_severity(self):
        result = score_findings([CRITICAL_FINDING, MEDIUM_FINDING])
        assert result.severity == Severity.CRITICAL

    def test_production_multiplier_increases_score(self):
        prod = score_findings([HIGH_FINDING], environment="production")
        dev = score_findings([HIGH_FINDING], environment="dev")
        assert prod.score > dev.score

    def test_score_capped_at_ten(self):
        many_criticals = [CRITICAL_FINDING] * 20
        result = score_findings(many_criticals)
        assert result.score <= 10.0

    def test_finding_counts_are_accurate(self):
        findings = [CRITICAL_FINDING, HIGH_FINDING, HIGH_FINDING, MEDIUM_FINDING]
        result = score_findings(findings)
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.finding_count == 4

    def test_high_severity_when_no_critical(self):
        result = score_findings([HIGH_FINDING, MEDIUM_FINDING])
        assert result.severity == Severity.HIGH

    def test_medium_severity_when_no_high(self):
        result = score_findings([MEDIUM_FINDING])
        assert result.severity == Severity.MEDIUM

    def test_info_severity_for_low_only(self):
        low = {"rule_id": "INFO-1", "severity": "LOW", "message": "Info"}
        result = score_findings([low])
        assert result.severity == Severity.LOW

    def test_staging_multiplier(self):
        staging = score_findings([HIGH_FINDING], environment="staging")
        prod = score_findings([HIGH_FINDING], environment="production")
        dev = score_findings([HIGH_FINDING], environment="dev")
        assert prod.score > staging.score > dev.score
