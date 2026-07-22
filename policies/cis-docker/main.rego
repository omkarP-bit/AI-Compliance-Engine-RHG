package ace.cis.docker

import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny) == 0

# CIS-DL-2.1 — container runs as root
deny[finding] if {
    input.metadata.user == ""
    finding := {
        "rule_id":   "CIS-DL-2.1",
        "severity":  "HIGH",
        "message":   "No USER directive — container runs as root",
        "patchable": false,
        "reference": "https://docs.docker.com/engine/reference/builder/#user"
    }
}

# CIS-DL-2.2 — no HEALTHCHECK
deny[finding] if {
    input.metadata.has_healthcheck == false
    finding := {
        "rule_id":   "CIS-DL-2.2",
        "severity":  "MEDIUM",
        "message":   "No HEALTHCHECK instruction found",
        "patchable": false,
        "reference": "https://docs.docker.com/engine/reference/builder/#healthcheck"
    }
}
