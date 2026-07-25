package ace.gha.security

import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny) == 0

# GHA-SEC-001 — write-all permissions at workflow level
deny[finding] if {
    input.permissions == "write-all"
    finding := {
        "rule_id":   "GHA-SEC-001",
        "severity":  "CRITICAL",
        "message":   "Workflow grants write-all permissions — use least-privilege scopes",
        "patchable": false,
        "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#considering-cross-repository-access"
    }
}

# GHA-SEC-002 — contents:write at workflow level without restriction
deny[finding] if {
    input.permissions.contents == "write"
    not input.permissions.pull_requests
    finding := {
        "rule_id":   "GHA-SEC-002",
        "severity":  "HIGH",
        "message":   "Workflow grants contents:write without restricting other scopes",
        "patchable": false,
        "reference": "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"
    }
}

# GHA-SEC-003 — third-party action pinned to mutable tag (not a SHA)
deny[finding] if {
    action_ref := input.metadata.uses_actions[_]
    not action_ref.sha_pinned
    not startswith(action_ref.action, "actions/")
    not startswith(action_ref.action, "github/")
    finding := {
        "rule_id":   "GHA-SEC-003",
        "severity":  "HIGH",
        "message":   sprintf("Third-party action '%v' pinned to mutable ref '%v' — use a full SHA digest", [action_ref.action, action_ref.pin]),
        "patchable": false,
        "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
    }
}

# GHA-SEC-004 — pull_request_target trigger (allows access to secrets from forks)
deny[finding] if {
    input.metadata.has_pull_request_target == true
    finding := {
        "rule_id":   "GHA-SEC-004",
        "severity":  "CRITICAL",
        "message":   "Workflow uses pull_request_target trigger which exposes repository secrets to fork PRs",
        "patchable": false,
        "reference": "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
    }
}

# GHA-SEC-005 — self-hosted runner (public repo risk)
deny[finding] if {
    job := input.metadata.jobs[_]
    job.self_hosted == true
    finding := {
        "rule_id":   "GHA-SEC-005",
        "severity":  "MEDIUM",
        "message":   sprintf("Job '%v' uses a self-hosted runner — verify isolation for public repos", [job.id]),
        "patchable": false,
        "reference": "https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners#self-hosted-runner-security"
    }
}

# GHA-SEC-006 — script injection via github.event.* in run steps
deny[finding] if {
    job  := input.metadata.jobs[_]
    step := job.run_steps[_]
    contains(step, "${{ github.event.")
    finding := {
        "rule_id":   "GHA-SEC-006",
        "severity":  "CRITICAL",
        "message":   sprintf("Job '%v' interpolates github.event.* directly into a run step — potential script injection", [job.id]),
        "patchable": false,
        "reference": "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"
    }
}
