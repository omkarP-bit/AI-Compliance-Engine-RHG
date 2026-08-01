package ace.cis.docker_compose

import future.keywords.if
import future.keywords.in

default allow := false

allow if count(deny) == 0

secret_key_patterns := ["password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "access_key", "access-key", "private_key", "private-key", "credential", "auth"]

weak_value_patterns := ["password123", "admin123", "root123", "123456", "qwerty", "letmein", "password", "admin", "root", "secret", "changeme"]

is_host_volume(vol) if {
    startswith(vol, "/")
}

is_host_volume(vol) if {
    startswith(vol, "./")
}

is_host_volume(vol) if {
    startswith(vol, "../")
}

is_host_volume(vol) if {
    startswith(vol, "~/")
}

port_is_public(port_str) if {
    not startswith(port_str, "127.0.0.1:")
    not startswith(port_str, "localhost:")
    not startswith(port_str, "::1:")
    not startswith(port_str, "127.0.0.1/")
}

# DC-1 — sensitive host directory mounted
deny[finding] if {
    svc := input.services[_]
    vol := svc.volumes[_]
    is_host_volume(vol)
    finding := {
        "rule_id":   "DC-1",
        "severity":  "HIGH",
        "message":   sprintf("Service %q mounts a host path into the container: %v", [svc.name, vol]),
        "patchable": false,
        "reference": "https://docs.docker.com/compose/compose-file/volumes/"
    }
}

# DC-2 — unnecessary Linux capabilities added
deny[finding] if {
    svc := input.services[_]
    cap := svc.cap_add[_]
    cap in {"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW", "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE"}
    finding := {
        "rule_id":   "DC-2",
        "severity":  "HIGH",
        "message":   sprintf("Service %q adds dangerous capability %q", [svc.name, cap]),
        "patchable": false,
        "reference": "https://docs.docker.com/engine/reference/commandline/run/#cap-add-add-linux-capabilities"
    }
}

# DC-3 — plaintext secret in environment
deny[finding] if {
    svc := input.services[_]
    key := object.keys(svc.environment)[_]
    key_lower := lower(key)
    some pattern in secret_key_patterns
    contains(key_lower, pattern)
    val := svc.environment[key]
    val != ""
    not startswith(val, "${")
    finding := {
        "rule_id":   "DC-3",
        "severity":  "HIGH",
        "message":   sprintf("Service %q has a plaintext secret in environment variable %q", [svc.name, key]),
        "patchable": true,
        "reference": "https://docs.docker.com/compose/environment-variables/"
    }
}

# DC-4 — weak/default credentials
deny[finding] if {
    svc := input.services[_]
    key := object.keys(svc.environment)[_]
    key_lower := lower(key)
    some pattern in secret_key_patterns
    contains(key_lower, pattern)
    val := svc.environment[key]
    some weak in weak_value_patterns
    val == weak
    finding := {
        "rule_id":   "DC-4",
        "severity":  "HIGH",
        "message":   sprintf("Service %q uses a weak/default credential in %q: %q", [svc.name, key, val]),
        "patchable": true,
        "reference": "https://docs.docker.com/compose/environment-variables/"
    }
}

# DC-5 — container runs as root
deny[finding] if {
    svc := input.services[_]
    svc.user == ""
    finding := {
        "rule_id":   "DC-5",
        "severity":  "MEDIUM",
        "message":   sprintf("Service %q runs as root (no USER directive)", [svc.name]),
        "patchable": true,
        "reference": "https://docs.docker.com/engine/reference/builder/#user"
    }
}

# DC-6 — privileged container
deny[finding] if {
    svc := input.services[_]
    svc.privileged == true
    finding := {
        "rule_id":   "DC-6",
        "severity":  "CRITICAL",
        "message":   sprintf("Service %q runs in privileged mode", [svc.name]),
        "patchable": false,
        "reference": "https://docs.docker.com/engine/reference/run/#security-configuration"
    }
}

# DC-7 — service port bound to all interfaces
deny[finding] if {
    svc := input.services[_]
    port := svc.ports[_]
    port_is_public(port)
    finding := {
        "rule_id":   "DC-7",
        "severity":  "MEDIUM",
        "message":   sprintf("Service %q exposes port %q on all interfaces (0.0.0.0)", [svc.name, port]),
        "patchable": true,
        "reference": "https://docs.docker.com/compose/compose-file/ports/"
    }
}

# DC-8 — Redis with protected-mode disabled
deny[finding] if {
    svc := input.services[_]
    contains(lower(svc.image), "redis")
    contains(lower(svc.command), "--protected-mode no")
    finding := {
        "rule_id":   "DC-8",
        "severity":  "HIGH",
        "message":   sprintf("Service %q runs Redis with protected-mode disabled (no authentication)", [svc.name]),
        "patchable": true,
        "reference": "https://redis.io/docs/management/security/"
    }
}