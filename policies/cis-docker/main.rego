package ace.cis.docker

import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny) == 0

# CIS-DL-1.1 — floating / mutable image tag
deny[finding] if {
    some i in input.instructions
    i.instruction == "FROM"
    not image_pinned(i.args)
    finding := {
        "rule_id":   "CIS-DL-1.1",
        "severity":  "MEDIUM",
        "message":   "Floating or unpinned base image tag (e.g. latest) — pin to a digest or explicit version",
        "patchable": false,
        "reference": "https://docs.docker.com/engine/reference/builder/#from"
    }
}

image_pinned(image) if {
    parts := split(image, ":")
    count(parts) == 2
    parts[1] != "latest"
    not contains(parts[1], "@")
}

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

# CIS-DL-2.3 — secrets hardcoded in ENV
deny[finding] if {
    some i in input.instructions
    i.instruction == "ENV"
    lower(i.args) == lower(i.args)  # no-op keeps rule analyzer-clean
    secret_in_env(i.args)
    finding := {
        "rule_id":   "CIS-DL-2.3",
        "severity":  "HIGH",
        "message":   sprintf("Likely secret hardcoded in ENV: %s", [key_name(i.args)]),
        "patchable": false,
        "reference": "https://docs.docker.com/reference/dockerfile/#env"
    }
}

secret_in_env(args) if contains(lower(args), "password")
secret_in_env(args) if contains(lower(args), "api_key")
secret_in_env(args) if contains(lower(args), "secret")
secret_in_env(args) if contains(lower(args), "token")
secret_in_env(args) if contains(lower(args), "credentials")

key_name(args) := name {
    parts := split(args, "=")
    name := trim(parts[0], " \t")
}

# CIS-DL-2.4 — ADD with remote URL
deny[finding] if {
    some i in input.instructions
    i.instruction == "ADD"
    startswith(lower(i.args), "http://")
    finding := {
        "rule_id":   "CIS-DL-2.4",
        "severity":  "HIGH",
        "message":   "ADD uses a remote URL — content is fetched unverified; prefer COPY of a vetted local file",
        "patchable": false,
        "reference": "https://docs.docker.com/reference/dockerfile/#add"
    }
}

deny[finding] if {
    some i in input.instructions
    i.instruction == "ADD"
    startswith(lower(i.args), "https://")
    finding := {
        "rule_id":   "CIS-DL-2.4",
        "severity":  "HIGH",
        "message":   "ADD uses a remote URL — content is fetched unverified; prefer COPY of a vetted local file",
        "patchable": false,
        "reference": "https://docs.docker.com/reference/dockerfile/#add"
    }
}

# CIS-DL-2.5 — piped remote script to shell
deny[finding] if {
    some i in input.instructions
    i.instruction == "RUN"
    remote_pipe_to_shell(i.args)
    finding := {
        "rule_id":   "CIS-DL-2.5",
        "severity":  "HIGH",
        "message":   "Piping a remote script directly into a shell — unverified code execution",
        "patchable": false,
        "reference": "https://www.cisecurity.org/benchmark/docker"
    }
}

remote_pipe_to_shell(args) if {
    startswith(lower(args), "curl")
    regex.match(`\|\s*(bash|sh)\b`, lower(args))
}

remote_pipe_to_shell(args) if {
    startswith(lower(args), "wget")
    regex.match(`\|\s*(bash|sh)\b`, lower(args))
}

remote_pipe_to_shell(args) if {
    startswith(lower(args), "curl")
    regex.match(`\|\s*sudo\s+(bash|sh)\b`, lower(args))
}