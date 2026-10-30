# ACE+RHG Video Demo Script (6-7 Minutes)

## Goal
Show the complete journey from understanding the problem to running a full gate on real code with all features.

## Setup Before Recording
- Clean terminal
- Have `samples/vulnerable-deploy.yaml` ready
- Have a real repo cloned (e.g., `/tmp/IoT-Network-Monitor` or any repo)
- Cloud URLs exported or local stack ready
- API key ready (or generate live)

---

## Script with Timing

### 1. INTRODUCTION (0:00 - 0:55) | ~55s
**Visual:** Show README or project structure

**Talk:**
*"ACE + RHG is an AI-Powered Compliance Engine and Release Hardening Gate. The idea is simple - catch security misconfigurations before they reach production. Instead of finding issues after deployment, we enforce compliance at the gate with automated remediation."*

**Show:** `ls` or open README briefly

### 2. PROBLEM STATEMENT & SOLUTION (0:55 - 1:25) | ~30s
**Visual:** Architecture diagram in mind or just explain

**Talk:**
*"Traditional security scans happen too late. ACE uses OPA with CIS, NIST policies to scan Kubernetes, Terraform, Dockerfiles, Helm, GitHub Actions. RHG acts as the enforcement gate - if issues are patchable, it auto-fixes them. If not, it blocks the deployment."*

**Show:** Quick look at `policies/` folder

### 3. PROJECT STRUCTURE & SETUP (1:25 - 2:00) | ~35s
**Visual:** Terminal

**Show:**
```bash
ace --version
ace init
```

**Talk:**
*"Let us look at the CLI. We have simple commands for everything. First, we need to set up our org, project and API key."*

### 4. ORG, PROJECT & API KEY SETUP (2:00 - 2:40) | ~40s
**Visual:** Terminal

**Show:**
```bash
export ACE_URL=https://fw6mh9jzpc.execute-api.ap-south-1.amazonaws.com
export RHG_URL=https://fw6mh9jzpc.execute-api.ap-south-1.amazonaws.com

ace create-org acme-corp --name "Acme Corporation"
ace add-repo acme-corp backend-api --repo acme-corp/backend-api
ace gen-key acme-corp backend-api --scopes scan,submit
```

**Talk:**
*"Creating an org, linking a repo (optional), and generating an API key is straightforward. The key is shown only once, so we save it securely."*

### 5. AUTHENTICATION & HEALTH CHECK (2:40 - 3:00) | ~20s
**Visual:** Terminal

**Show:**
```bash
export ACE_API_KEY=ace_sk_...
ace whoami
ace health
```

**Talk:**
*"Authenticate and verify both ACE and RHG services are up and running."*

### 6. SCANNING A VULNERABLE FILE (3:00 - 3:40) | ~40s
**Visual:** Terminal

**Show:**
```bash
cat samples/vulnerable-deploy.yaml
ace scan samples/vulnerable-deploy.yaml
```

**Talk:**
*"Let us look at a vulnerable Kubernetes deployment - privileged container, running as root, no resource limits. ACE scans it against CIS Kubernetes benchmarks and gives us detailed findings with severity, rule IDs and descriptions."*

### 7. AUTO-PATCHING DEMO (3:40 - 4:15) | ~35s
**Visual:** Terminal

**Show:**
```bash
ace scan-and-mutate samples/vulnerable-deploy.yaml
```

**Talk:**
*"Before going to gate, we can see what patches would be generated. ACE creates RFC6902 patches to fix issues like adding resource limits, dropping privileges, running as non-root."*

### 8. FULL GATE SUBMISSION (4:15 - 5:15) | ~60s - CRITICAL
**Visual:** Terminal (focus on output)

**Show:**
```bash
ace submit samples/vulnerable-deploy.yaml --repo acme-corp/backend-api --branch main --env prod --fail-on HIGH
```

**Talk:**
*"This is the main feature - ace submit does everything. It scans, attempts to auto-remediate, re-evaluates, and makes a gate decision. Here we see PATCHED - violations were auto-fixed by AI. It shows scan ID, mutations applied, and patched artifacts. If unfixable issues remain above threshold, it would BLOCK."*

### 9. REAL REPO SCAN (5:15 - 5:50) | ~35s
**Visual:** Terminal

**Show:**
```bash
cd /home/OmkarArch/Documents/DevOPS/Cloud-native\ Network\ Sniffing/IoT-Network-Monitor
ace scan --all --fail-on HIGH
```

**Talk:**
*"Let us test on a real repository. ACE can scan everything with --all flag, or use --infra and --backend flags to be selective."*

### 9a. BACKEND + INFRA COMBINED SCANNING (5:50 - 6:10) | ~20s - KEY FEATURE
**Visual:** Terminal

**Show:**
```bash
ace submit --infra --backend --repo omkarP-bit/IoT-Network-Monitor --branch main --env prod --fail-on HIGH
```

**Talk:**
*"The core strength - ACE doesn't just scan IaC. With --infra and --backend flags, or --backend-path, we can scan both infrastructure manifests AND application source code together. The gate evaluates combined risk from both layers. This gives true end-to-end coverage."*

### 10. HISTORY & TRACEABILITY (5:50 - 6:15) | ~25s
**Visual:** Terminal

**Show:**
```bash
ace history --limit 8
```

**Talk:**
*"Full audit trail - every scan, gate decision, mutation is tracked with timestamps, repo, branch. Combined with git history for complete visibility."*

### 11. CONCLUSION (6:15 - 6:50) | ~35s
**Visual:** Terminal showing help or summary

**Show:**
```bash
ace --help
```

**Talk:**
*"ACE+RHG brings policy-as-code, AI-powered remediation, and automated gating together. Easy CLI, works locally with Docker or in cloud via API Gateway. It prevents misconfigurations from reaching production while saving time by auto-fixing what's safe to fix. This is shift-left security done right. Thank you."*

## Recording Tips
- Speak naturally, don't rush through outputs
- Pause for 2-3 seconds after showing important outputs (risk score, decision)
- Use the cloud endpoints for smoother demo
- Keep terminal font readable
- Show both the vulnerable input and the gate decision clearly
- Emphasize "PATCHED" vs "BLOCK" difference
- Show the actual patches being applied count
