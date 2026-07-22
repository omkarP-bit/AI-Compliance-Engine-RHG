package ace.cis.kubernetes

import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny) == 0

deny[finding] if {
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    finding := {
        "rule_id":   "CIS-K8S-5.2.1",
        "severity":  "HIGH",
        "message":   sprintf("Privileged container: %v", [container.name]),
        "patchable": true,
        "reference": "https://kubernetes.io/docs/concepts/security/pod-security-admission/"
    }
}

deny[finding] if {
    container := input.spec.containers[_]
    container.securityContext.runAsUser == 0
    finding := {
        "rule_id":   "CIS-K8S-5.2.2",
        "severity":  "HIGH",
        "message":   sprintf("Container runs as root (UID 0): %v", [container.name]),
        "patchable": true,
        "reference": "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"
    }
}

deny[finding] if {
    container := input.spec.containers[i]
    not container.resources.limits.cpu
    finding := {
        "rule_id":   "CIS-K8S-5.4.1",
        "severity":  "MEDIUM",
        "message":   sprintf("No CPU limit on container: %v", [container.name]),
        "patchable": true,
        "reference": "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
    }
}

deny[finding] if {
    container := input.spec.containers[i]
    not container.resources.limits.memory
    finding := {
        "rule_id":   "CIS-K8S-5.4.2",
        "severity":  "MEDIUM",
        "message":   sprintf("No memory limit on container: %v", [container.name]),
        "patchable": true,
        "reference": "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
    }
}

deny[finding] if {
    container := input.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    finding := {
        "rule_id":   "CIS-K8S-5.2.5",
        "severity":  "MEDIUM",
        "message":   sprintf("Privilege escalation allowed: %v", [container.name]),
        "patchable": true,
        "reference": "https://kubernetes.io/docs/concepts/security/pod-security-admission/#privilege-escalation"
    }
}

deny[finding] if {
    input.spec.hostNetwork == true
    finding := {
        "rule_id":   "CIS-K8S-5.2.4",
        "severity":  "CRITICAL",
        "message":   "Pod uses host network namespace",
        "patchable": false,
        "reference": "https://kubernetes.io/docs/concepts/security/pod-security-admission/#host-namespaces"
    }
}

patch[op] if {
    container := input.spec.containers[i]
    container.securityContext.privileged == true
    op := {"op": "replace", "path": sprintf("/spec/containers/%d/securityContext/privileged", [i]), "value": false}
}

patch[op] if {
    container := input.spec.containers[i]
    container.securityContext.privileged == true
    op := {"op": "add", "path": sprintf("/spec/containers/%d/securityContext/runAsNonRoot", [i]), "value": true}
}

patch[op] if {
    container := input.spec.containers[i]
    container.securityContext.runAsUser == 0
    op := {"op": "replace", "path": sprintf("/spec/containers/%d/securityContext/runAsUser", [i]), "value": 1000}
}

patch[op] if {
    container := input.spec.containers[i]
    not container.resources.limits.cpu
    op := {"op": "add", "path": sprintf("/spec/containers/%d/resources/limits/cpu", [i]), "value": "500m"}
}

patch[op] if {
    container := input.spec.containers[i]
    not container.resources.limits.memory
    op := {"op": "add", "path": sprintf("/spec/containers/%d/resources/limits/memory", [i]), "value": "256Mi"}
}

patch[op] if {
    container := input.spec.containers[i]
    container.securityContext.allowPrivilegeEscalation == true
    op := {"op": "replace", "path": sprintf("/spec/containers/%d/securityContext/allowPrivilegeEscalation", [i]), "value": false}
}
