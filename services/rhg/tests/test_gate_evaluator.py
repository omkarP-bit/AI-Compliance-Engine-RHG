from rhg.gate.evaluator import GateDecision, GateEvaluator


class TestGateEvaluator:
    def setup_method(self):
        self.evaluator = GateEvaluator(block_on="HIGH")

    def test_allow_when_no_findings(self):
        result = self.evaluator.evaluate([], risk_score=0.0, overall_severity="INFO")
        assert result.decision == GateDecision.ALLOW
        assert len(result.blocking_findings) == 0

    def test_allow_when_below_threshold(self):
        findings = [{"rule_id": "LOW-1", "severity": "LOW", "message": "Minor issue"}]
        result = self.evaluator.evaluate(findings, risk_score=1.5, overall_severity="LOW")
        assert result.decision == GateDecision.ALLOW
        assert len(result.blocking_findings) == 0

    def test_block_on_critical(self):
        findings = [
            {"rule_id": "CIS-K8S-5.2.4", "severity": "CRITICAL", "message": "Host network"}
        ]
        result = self.evaluator.evaluate(findings, risk_score=9.0, overall_severity="CRITICAL")
        assert result.decision == GateDecision.BLOCK
        assert len(result.blocking_findings) == 1

    def test_block_on_high(self):
        findings = [
            {"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH", "message": "Privileged"}
        ]
        result = self.evaluator.evaluate(findings, risk_score=7.5, overall_severity="HIGH")
        assert result.decision == GateDecision.BLOCK
        assert len(result.blocking_findings) == 1

    def test_patched_when_mutations_applied_and_no_blocking(self):
        findings = [{"rule_id": "LOW-1", "severity": "LOW", "message": "Low issue"}]
        result = self.evaluator.evaluate(findings, risk_score=1.5, overall_severity="LOW", mutations_applied=2)
        assert result.decision == GateDecision.PATCHED
        assert len(result.blocking_findings) == 0

    def test_block_only_above_threshold(self):
        findings = [
            {"rule_id": "LOW-1", "severity": "LOW", "message": "Low"},
            {"rule_id": "HIGH-1", "severity": "HIGH", "message": "High"},
            {"rule_id": "MED-1", "severity": "MEDIUM", "message": "Medium"},
        ]
        result = self.evaluator.evaluate(findings, risk_score=5.0, overall_severity="HIGH")
        assert result.decision == GateDecision.BLOCK
        assert len(result.blocking_findings) == 1
        assert result.blocking_findings[0]["rule_id"] == "HIGH-1"

    def test_critical_threshold_only_blocks_critical(self):
        evaluator = GateEvaluator(block_on="CRITICAL")
        findings = [
            {"rule_id": "HIGH-1", "severity": "HIGH", "message": "High"},
            {"rule_id": "MED-1", "severity": "MEDIUM", "message": "Medium"},
        ]
        result = evaluator.evaluate(findings, risk_score=5.0, overall_severity="HIGH")
        assert result.decision == GateDecision.ALLOW
        assert len(result.blocking_findings) == 0

    def test_should_retry_mutation_when_improved(self):
        assert self.evaluator.should_retry_mutation(0, [{"a": 1}, {"b": 2}], [{"a": 1}]) is True

    def test_should_not_retry_mutation_when_max_reached(self):
        assert self.evaluator.should_retry_mutation(3, [{"a": 1}], []) is False

    def test_should_not_retry_when_no_improvement(self):
        assert self.evaluator.should_retry_mutation(0, [{"a": 1}], [{"a": 1}]) is False

    def test_should_not_retry_when_worse(self):
        assert self.evaluator.should_retry_mutation(0, [{"a": 1}], [{"a": 1}, {"b": 2}]) is False
