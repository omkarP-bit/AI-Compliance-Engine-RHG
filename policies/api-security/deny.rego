package ace.api.security

import future.keywords.if
import future.keywords.in

# Default allow - rely on regex scanner in ACE for line-level findings
# OPA policies here for structural patterns when possible
default allow := true

deny[msg] {
    # Placeholder - regex scanner provides detailed line-level findings
    false
    msg := {
        "rule_id": "API-SEC-OPA-000",
        "title": "API security check",
        "description": "placeholder",
        "severity": "INFO",
        "remediation": "N/A"
    }
}
