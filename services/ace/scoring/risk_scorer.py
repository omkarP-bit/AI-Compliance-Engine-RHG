from enum import Enum
from dataclasses import dataclass


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.5,
    Severity.INFO: 0.5,
}

ENVIRONMENT_MULTIPLIERS = {
    "production": 1.5,
    "staging": 1.0,
    "dev": 0.6,
}


@dataclass
class RiskResult:
    score: float
    severity: Severity
    finding_count: int
    critical_count: int
    high_count: int


def score_findings(findings: list[dict], environment: str = "production") -> RiskResult:
    if not findings:
        return RiskResult(0.0, Severity.INFO, 0, 0, 0)

    env_mult = ENVIRONMENT_MULTIPLIERS.get(environment, 1.0)
    severity_counts: dict[Severity, int] = {s: 0 for s in Severity}

    for f in findings:
        sev = Severity(f.get("severity", "LOW"))
        severity_counts[sev] += 1

    raw_score = sum(
        SEVERITY_WEIGHTS[sev] * count
        for sev, count in severity_counts.items()
    )

    score = min(10.0, (raw_score / max(len(findings), 1)) * env_mult)

    if severity_counts[Severity.CRITICAL] > 0:
        overall = Severity.CRITICAL
    elif severity_counts[Severity.HIGH] > 0:
        overall = Severity.HIGH
    elif severity_counts[Severity.MEDIUM] > 0:
        overall = Severity.MEDIUM
    elif severity_counts[Severity.LOW] > 0:
        overall = Severity.LOW
    else:
        overall = Severity.INFO

    return RiskResult(
        score=round(score, 2),
        severity=overall,
        finding_count=len(findings),
        critical_count=severity_counts[Severity.CRITICAL],
        high_count=severity_counts[Severity.HIGH],
    )
