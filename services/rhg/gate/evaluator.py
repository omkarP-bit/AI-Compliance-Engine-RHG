from dataclasses import dataclass
from enum import Enum
from typing import Optional


class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    PATCHED = "PATCHED"


class BlockOnSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


@dataclass
class GateResult:
    decision: GateDecision
    blocking_findings: list[dict]
    risk_score: float
    overall_severity: str


class GateEvaluator:
    def __init__(self, block_on: str = "HIGH", max_mutation_retries: int = 3):
        self.block_on = block_on
        self.max_mutation_retries = max_mutation_retries

    def evaluate(
        self,
        findings: list[dict],
        risk_score: float,
        overall_severity: str,
        mutations_applied: int = 0,
    ) -> GateResult:
        threshold = SEVERITY_ORDER.get(self.block_on, 3)
        blocking = []

        for f in findings:
            sev = f.get("severity", "INFO")
            if SEVERITY_ORDER.get(sev, 0) >= threshold:
                blocking.append(f)

        if not blocking:
            if mutations_applied > 0:
                return GateResult(GateDecision.PATCHED, [], risk_score, overall_severity)
            return GateResult(GateDecision.ALLOW, [], risk_score, overall_severity)

        return GateResult(GateDecision.BLOCK, blocking, risk_score, overall_severity)

    def should_retry_mutation(self, retry_count: int, pre_patch_findings: list[dict], post_patch_findings: list[dict]) -> bool:
        if retry_count >= self.max_mutation_retries:
            return False
        post_count = len(post_patch_findings)
        pre_count = len(pre_patch_findings)
        return post_count < pre_count
