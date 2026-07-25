<div align="center">

<svg viewBox="0 0 680 340" width="340" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <clipPath id="sc">
      <path d="M340 52 L440 90 L440 198 Q440 252 340 280 Q240 252 240 198 L240 90 Z"/>
    </clipPath>
  </defs>
  <path d="M340 48 L444 88 L444 200 Q444 258 340 286 Q236 258 236 200 L236 88 Z" fill="none" stroke="#534AB7" stroke-width="2.5"/>
  <path d="M340 52 L440 90 L440 198 Q440 252 340 280 Q240 252 240 198 L240 90 Z" fill="#EEEDFE"/>
  <g clip-path="url(#sc)" stroke="#AFA9EC" stroke-width="1" fill="none">
    <line x1="240" y1="130" x2="440" y2="130"/>
    <line x1="240" y1="168" x2="440" y2="168"/>
    <line x1="250" y1="208" x2="430" y2="208"/>
    <line x1="290" y1="88" x2="290" y2="280"/>
    <line x1="340" y1="52" x2="340" y2="286"/>
    <line x1="390" y1="88" x2="390" y2="280"/>
    <circle cx="290" cy="130" r="4" fill="#7F77DD" stroke="none"/>
    <circle cx="340" cy="130" r="4" fill="#7F77DD" stroke="none"/>
    <circle cx="390" cy="130" r="4" fill="#7F77DD" stroke="none"/>
    <circle cx="290" cy="168" r="4" fill="#1D9E75" stroke="none"/>
    <circle cx="340" cy="168" r="4" fill="#1D9E75" stroke="none"/>
    <circle cx="390" cy="168" r="4" fill="#1D9E75" stroke="none"/>
    <circle cx="290" cy="208" r="4" fill="#D85A30" stroke="none"/>
    <circle cx="340" cy="208" r="4" fill="#D85A30" stroke="none"/>
    <circle cx="390" cy="208" r="4" fill="#D85A30" stroke="none"/>
  </g>
  <rect x="323" y="152" width="34" height="28" rx="4" fill="#534AB7"/>
  <path d="M329 152 L329 143 Q329 133 340 133 Q351 133 351 143 L351 152" fill="none" stroke="#534AB7" stroke-width="3" stroke-linecap="round"/>
  <circle cx="340" cy="164" r="4" fill="#EEEDFE"/>
  <rect x="338" y="164" width="4" height="7" rx="1" fill="#EEEDFE"/>
  <text x="340" y="316" text-anchor="middle" font-family="system-ui,sans-serif" font-size="22" font-weight="600" letter-spacing="6" fill="#3C3489">ACE+RHG</text>
  <text x="340" y="336" text-anchor="middle" font-family="system-ui,sans-serif" font-size="11" font-weight="400" letter-spacing="2" fill="#888780">AI COMPLIANCE ENGINE · RELEASE HARDENING GATE</text>
</svg>

# ACE + RHG

**Agentic AI Compliance Engine & Release Hardening Gate**

A production-grade DevSecOps platform that enforces security compliance inside CI/CD pipelines — before any artifact reaches production.

<br/>

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![OPA](https://img.shields.io/badge/OPA-0.63-7F77DD?style=flat-square&logo=openpolicyagent&logoColor=white)](https://openpolicyagent.org)
[![LangGraph](https://img.shields.io/badge/LangGraph-agentic-1D9E75?style=flat-square)](https://langchain-ai.github.io/langgraph/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-EKS-326CE5?style=flat-square&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-FF9900?style=flat-square&logo=awslambda&logoColor=white)](https://aws.amazon.com/lambda/)
[![License](https://img.shields.io/badge/License-MIT-6B7280?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-pytest-0F6E56?style=flat-square&logo=pytest&logoColor=white)](https://pytest.org)

<br/>

[Overview](#-overview) · [How it works](#-how-it-works) · [Quick start](#-quick-start) · [Supported artifacts](#-supported-artifacts) · [Compliance standards](#-compliance-standards) · [Tech stack](#-tech-stack) · [Phases](#-build-phases) · [Contributing](#-contributing)

</div>

---

## 🛡️ Overview

Modern engineering teams ship fast — but speed creates blind spots. Misconfigured Kubernetes pods, over-permissive IAM roles, secrets in environment variables, and container images with critical CVEs routinely make it to production because traditional compliance checks happen *after* deployment.

**ACE+RHG flips that model entirely.**

Every time a developer pushes code, the system submits all deployment artifacts to a two-component enforcement engine:

- **ACE (AI Compliance Engine)** — scans artifacts using OPA/Rego policy bundles against CIS, NIST, and ISO standards, then enriches findings with a LangGraph multi-agent system that reasons about context, cross-artifact risk, and CVE data.
- **RHG (Release Hardening Gate)** — acts as the enforcement layer, deciding whether a release proceeds. For patchable violations, it invokes OPA's mutation engine to auto-fix the artifact and re-scan. For unresolvable findings, it blocks the pipeline and routes to a human review queue.

Everything — every scan, finding, mutation, agent action, and gate decision — is visible in a Grafana-based observability dashboard and delivered as real-time Slack alerts.

```
git push  →  CI/CD  →  RHG  →  ACE (OPA + Agents)  →  ALLOW / PATCH / BLOCK
                                        ↓
                              Grafana dashboard + Slack alerts
```

---

## ✨ Key features

| Feature | Description |
|---|---|
| **OPA-first policy engine** | All rules live in version-controlled Rego bundles — testable, auditable, swappable |
| **Self-healing artifacts** | OPA mutation emits JSON Patch (RFC 6902) to auto-fix violations without human intervention |
| **Agentic intelligence** | LangGraph agents handle what rules can't — contextual reasoning, CVE enrichment, drift detection |
| **MCP tool orchestration** | Agents call tools via Model Context Protocol — OPA, kubectl, Trivy, AWS APIs, all unified |
| **Human-in-the-loop** | Escalated decisions land in a React review queue — not buried in logs |
| **Real-time alerts** | Slack Block Kit messages + SQS queue for durable delivery to downstream consumers |
| **Framework-agnostic** | HTTP service + CLI means any language (Python, Node, Go) integrates via one CI step |
| **Lambda-native** | Full serverless deployment via AWS Lambda + API Gateway — zero infrastructure to manage for web users |
| **Packageable** | Designed for distribution as `pip install ace-compliance` and `npm install ace-compliance` |

---

## ⚙️ How it works

### The pipeline gate

```
Developer commit
      │
      ▼
CI/CD pipeline (GitHub Actions / GitLab / Jenkins)
      │
      ▼
Artifact generation
(Kubernetes YAML · Terraform · Helm · Dockerfile)
      │
      ▼
┌─────────────────────────────────────────────────┐
│           Release Hardening Gate (RHG)          │
│                                                 │
│  ┌─────────────┐   scan   ┌──────────────────┐  │
│  │  Artifact   │ ───────► │  AI Compliance   │  │
│  │  receiver   │ ◄─────── │  Engine (ACE)    │  │
│  └─────────────┘ findings │                  │  │
│         │                 │  OPA rule engine  │  │
│         ▼                 │  LangGraph agents │  │
│  Gate policy eval         │  Risk scorer      │  │
│         │                 └──────────────────┘  │
│    ┌────┴─────┐                                  │
│  patchable  unresolvable                         │
│    │              │                              │
│    ▼              ▼                              │
│  OPA mutate  Human review                       │
│  + re-scan   queue                              │
│    │                                             │
│  ALLOW ──────────────────────────────────────►  │
│  BLOCK (+ report) ───────────────────────────►  │
└─────────────────────────────────────────────────┘
      │
      ▼
Prometheus + Grafana + Slack alerts
```

### OPA mutation (self-healing)

When a violation is found and flagged as patchable, OPA emits a JSON Patch alongside the denial:

```json
{
  "deny": ["CIS-K8S-5.2.1: Privileged container detected"],
  "patch": [
    { "op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": false },
    { "op": "add",     "path": "/spec/containers/0/securityContext/runAsNonRoot", "value": true }
  ]
}
```

RHG applies the patch, writes the corrected artifact back to the pipeline workspace, re-queues the scan, and if the patched artifact passes — the pipeline continues with **zero developer intervention**. Every mutation is logged with a full before/after diff in the audit trail.

### Slack alert example

For every gate decision, the alert channel receives a structured Block Kit message:

```
🟡 ACE Security Gate — org/payments-service

Decision:    🔧 Auto-patched and allowed
Environment: production
Severity:    HIGH
Findings:    3 violations

Blocking rules:
  • CIS-K8S-5.2.1
  • CIS-K8S-5.2.2

Auto-mutations applied: 3 patches

[ View Full Report → ]
```

---

## 🚀 Quick start

### Local development (Docker Compose)

```bash
# 1. Clone the repo
git clone https://github.com/omkarP-bit/ace-rhg
cd ace-rhg

# 2. Set environment variables
cp .env.example .env
# Fill in: ANTHROPIC_API_KEY, SLACK_WEBHOOK_URL

# 3. Start the full stack
docker-compose up -d

# Services:
# ACE API    →  http://localhost:8000/docs
# RHG API    →  http://localhost:8001/docs
# Dashboard  →  http://localhost:3000
# Grafana    →  http://localhost:3001
# OPA        →  http://localhost:8181
```

### CLI scan

```bash
# Install
pip install ace-compliance

# Scan a directory
ace scan ./k8s/ --env production --fail-on HIGH

# Scan a single file with JSON output
ace scan ./terraform/main.tf --output json

# Example output:
# ============================================================
#   ACE Scan Report
#   Risk Score:  8.4/10
#   Severity:    HIGH
#   Findings:    3 violations
# ============================================================
#   [HIGH] CIS-K8S-5.2.1  deployment.yaml
#          Privileged container detected: app
#
#   [HIGH] CIS-K8S-5.2.2  deployment.yaml
#          Container runs as root (UID 0): app
```

### GitHub Actions

```yaml
# .github/workflows/deploy.yml

- name: ACE compliance scan
  uses: omkarP-bit/ace-rhg/.github/actions/ace-scan@v1
  with:
    environment: production
    fail-on: HIGH
    artifacts-path: ./k8s
```

### API (direct)

```bash
curl -X POST http://localhost:8000/ace/scan \
  -H "Content-Type: application/json" \
  -d '{
    "pipeline_id": "my-pipeline-001",
    "environment": "production",
    "artifacts": [{
      "type": "kubernetes",
      "name": "deployment.yaml",
      "content": "'$(base64 -w0 ./k8s/deployment.yaml)'"
    }],
    "policy_bundles": ["cis-kubernetes@v1.8"]
  }'
```

---

## 📦 Supported artifacts

| Artifact type | Extensions | Policy bundle | Auto-mutation |
|---|---|---|---|
| Kubernetes manifests | `.yaml`, `.yml` | `cis-kubernetes@v1.8` | ✅ |
| Terraform plans | `.tf`, `.tf.json`, `tfplan.json` | `cis-terraform@v1.4` | ✅ |
| Helm charts | `.yaml` (templates) | `cis-kubernetes@v1.8` | ✅ |
| Dockerfiles | `Dockerfile`, `*.dockerfile` | `cis-docker@v1.6` | ✅ |

Future: AWS CloudFormation · Ansible playbooks · GitHub Actions workflows · Kustomize overlays

---

## 📋 Compliance standards

| Standard | Version | Coverage |
|---|---|---|
| CIS Kubernetes Benchmark | v1.8 | Privileged containers, host namespaces, capabilities, seccomp, AppArmor, resource limits |
| CIS Docker Benchmark | v1.6 | Base image hygiene, root user, exposed ports, secrets in layers, resource limits |
| NIST SP 800-53 | Rev 5 | AC (access control), CM (configuration management), AU (audit logging), SI (system integrity) |
| ISO/IEC 27001 | 2022 | Risk management, asset protection, security governance |
| Custom Rego bundles | — | Teams ship their own `.rego` files; ACE loads them via OPA's bundle API |

---

## 🏗️ Tech stack

```
Backend          FastAPI 0.111 · Python 3.12 · Pydantic v2
Policy engine    Open Policy Agent 0.63 · Rego
Agent layer      LangGraph · LangChain · Claude claude-sonnet-4-6 (Anthropic)
Orchestration    MCP (Model Context Protocol) server
Task queue       Celery · Redis 7
Event bus        Redis Pub/Sub → WebSocket (FastAPI)
Databases        PostgreSQL 16 (audit trail) · Redis 7 (cache)
Observability    Prometheus · Grafana · structlog (JSON)
Alerting         Slack Block Kit · AWS SQS · PagerDuty
Infrastructure   Docker · Kubernetes · AWS EKS · Terraform
Serverless       AWS Lambda (Mangum adapter) · API Gateway v2
Dashboard        React 18 · TypeScript · Tailwind CSS · Recharts
CI/CD            GitHub Actions · GitLab CI · Jenkins · ArgoCD
Distribution     PyPI (pip install ace-compliance) · npm (ace-compliance)
```

---

## 🔌 Integrations

<table>
<tr>
<td><b>CI/CD platforms</b></td>
<td>GitHub Actions · GitLab CI/CD · Jenkins · Azure DevOps · ArgoCD · Tekton</td>
</tr>
<tr>
<td><b>Alert channels</b></td>
<td>Slack (Block Kit) · AWS SQS · PagerDuty · Email (SMTP)</td>
</tr>
<tr>
<td><b>Cloud providers</b></td>
<td>AWS (EKS, Lambda, SQS, ECR, RDS) · GCP (planned) · Azure (planned)</td>
</tr>
<tr>
<td><b>Security tools</b></td>
<td>Trivy (CVE scanning) · OPA (policy engine) · Grype (vulnerability DB)</td>
</tr>
<tr>
<td><b>Observability</b></td>
<td>Prometheus · Grafana · Datadog (planned) · OpenTelemetry (planned)</td>
</tr>
</table>

---

## 🗺️ Build phases

| Phase | Status | Deliverable |
|---|---|---|
| **1 — Core engine** | 🔨 In progress | FastAPI ACE service, OPA client, parser layer, Rego bundles, risk scorer |
| **2 — Mutation engine** | 📋 Planned | Self-healing artifacts, JSON Patch pipeline, mutation audit trail |
| **3 — Agentic AI layer** | 📋 Planned | LangGraph agents, MCP server, PR review agent, drift detection agent |
| **4 — RHG + CLI** | 📋 Planned | CI/CD native integrations, `ace` CLI, policy-as-code workflow |
| **5 — Observability** | 📋 Planned | Grafana dashboards, WebSocket feed, human review queue |
| **6 — Alert system** | 📋 Planned | Slack Block Kit, SQS queue, alert router with multi-channel support |
| **7 — Lambda deploy** | 📋 Planned | Serverless packaging, API Gateway, Lambda container images |
| **8 — SDK packaging** | 📋 Planned | `pip install ace-compliance` · `npm install ace-compliance` |

---

## 📁 Repository structure

```
ace-rhg/
├── CLAUDE.md               ← system architecture and API contracts
├── DEVELOPMENT.md          ← phased build guide with unit tests
├── README.md               ← you are here
├── docker-compose.yml
│
├── services/
│   ├── ace/                ← AI Compliance Engine (FastAPI)
│   │   ├── api/            ← REST + WebSocket routes
│   │   ├── parsers/        ← YAML / HCL / Dockerfile parsers
│   │   ├── agents/         ← LangGraph agent definitions
│   │   ├── mcp/            ← MCP server and tool registry
│   │   ├── engine/         ← OPA client, rule engine
│   │   ├── scoring/        ← risk scorer
│   │   ├── alerts/         ← Slack, SQS, alert router
│   │   └── tests/
│   │
│   ├── rhg/                ← Release Hardening Gate (FastAPI)
│   │   ├── api/
│   │   ├── gate/           ← policy evaluator
│   │   ├── mutator/        ← JSON Patch engine
│   │   └── tests/
│   │
│   └── dashboard/          ← React observability UI
│       └── src/
│           ├── components/
│           └── ws/         ← WebSocket client
│
├── policies/               ← OPA Rego bundles (version-controlled)
│   ├── cis-kubernetes/
│   ├── cis-docker/
│   ├── nist-800-53/
│   └── custom/             ← org-specific rules
│
├── infra/
│   ├── terraform/          ← AWS EKS + Lambda + API Gateway
│   ├── helm/               ← ACE+RHG Helm chart
│   ├── docker/             ← Dockerfiles (app + Lambda image)
│   └── grafana/dashboards/ ← provisioned dashboard JSON
│
└── cli/                    ← ace-compliance CLI (PyPI)
    └── ace_compliance/
```

---

## 🧪 Testing

```bash
# Run all tests with coverage
pytest services/ cli/ infra/lambda/ \
  -v --cov=services --cov-report=term-missing \
  --cov-fail-under=75

# Run OPA Rego policy tests
opa test policies/ -v

# Run specific phase tests
pytest services/ace/tests/ -v                 # Phase 1
pytest services/rhg/tests/test_patch*.py -v  # Phase 2
pytest services/ace/tests/test_agents.py -v  # Phase 3
pytest cli/tests/ -v                          # Phase 4
pytest services/ace/tests/test_alerts.py -v  # Phase 6
```

Expected output:
```
services/ace/tests/test_parsers.py    ✓  5 passed
services/ace/tests/test_risk_scorer.py ✓  5 passed
services/ace/tests/test_opa_client.py  ✓  4 passed
services/ace/tests/test_scan_api.py    ✓  3 passed
services/rhg/tests/test_patch_engine.py ✓  6 passed
services/ace/tests/test_agents.py      ✓  4 passed
services/ace/tests/test_alerts.py      ✓  7 passed

Coverage: 81%
```

---

## 🌐 Lambda deployment (serverless)

ACE+RHG ships as a container image deployable to AWS Lambda via [Mangum](https://mangum.io/) — the same FastAPI codebase runs locally, in Kubernetes, and in Lambda with zero changes.

```bash
# Build Lambda container image
make build

# Push to ECR and deploy via Terraform
make push IMAGE_TAG=v0.1.0
make deploy-lambda ENV=production IMAGE_TAG=v0.1.0

# After deploy:
# POST https://<api-id>.execute-api.ap-south-1.amazonaws.com/ace/scan
```

**Lambda architecture:**

```
Web user / IDE plugin / npm SDK / pip SDK
              │
              ▼
   API Gateway v2 (HTTP API)
              │
     ┌────────┴──────────┐
     ▼                   ▼
Lambda: ace-scan    Lambda: ace-mutate
  (512 MB, 60s)      (512 MB, 60s)
     │                   │
     └────────┬──────────┘
              ▼
    SQS FIFO alert queue
              │
              ▼
Lambda: alert-dispatcher
    │              │
    ▼              ▼
  Slack         PagerDuty
```

---

## 🤝 Contributing

Contributions are welcome — especially new Rego policy bundles for additional artifact types and cloud providers.

```bash
# Set up dev environment
git clone https://github.com/omkarP-bit/ace-rhg
cd ace-rhg
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install

# Run tests before submitting a PR
make test && make test-policies
```

**Contribution areas:**

- New Rego policies (CloudFormation, Ansible, GitHub Actions workflows)
- Additional parser implementations
- Agent specializations (PR review, dependency audit)
- Grafana dashboard improvements
- GCP / Azure provider support

Please read `DEVELOPMENT.md` before contributing — it covers the full phased architecture, test conventions, and API contracts.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ❤️ by [Omkar](https://github.com/omkarP-bit) · VIT Pune, AI & Data Science

<br/>

*Shift security left. Ship with confidence.*

</div>
