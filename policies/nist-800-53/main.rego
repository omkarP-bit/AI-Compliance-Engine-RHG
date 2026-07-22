package ace.nist

import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny) == 0

# AC-6 — least privilege: containers should not run as root
deny[finding] if {
    container := input.spec.containers[_]
    container.securityContext.runAsUser == 0
    finding := {
        "rule_id":   "NIST-AC-6",
        "severity":  "HIGH",
        "message":   sprintf("Least privilege violation — container runs as root: %v", [container.name]),
        "patchable": true,
        "reference": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
    }
}

# CM-2 — baseline configuration: missing resource limits
deny[finding] if {
    container := input.spec.containers[_]
    not container.resources.limits
    finding := {
        "rule_id":   "NIST-CM-2",
        "severity":  "MEDIUM",
        "message":   sprintf("Missing resource limits — no baseline configured: %v", [container.name]),
        "patchable": true,
        "reference": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
    }
}

# SI-7 — software integrity: privileged containers increase attack surface
deny[finding] if {
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    finding := {
        "rule_id":   "NIST-SI-7",
        "severity":  "HIGH",
        "message":   sprintf("Privileged container violates integrity controls: %v", [container.name]),
        "patchable": true,
        "reference": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
    }
}
