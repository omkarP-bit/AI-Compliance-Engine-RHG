# ACE + RHG

**AI Compliance Engine + Release Hardening Gate**

An agentic DevSecOps platform that scans cloud-native deployment artifacts, detects security and compliance violations, proposes context-aware remediations, and enforces release policies directly within CI/CD pipelines — before artifacts reach production.

[![Tests](https://img.shields.io/badge/Tests-355%20passing-0F6E56?style=flat-square&logo=pytest&logoColor=white)](https://pytest.org)
[![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![OPA](https://img.shields.io/badge/Policy-Open%20Policy%20Agent-7D58C1?style=flat-square)](https://www.openpolicyagent.org/)
[![LangGraph](https://img.shields.io/badge/Agents-LangGraph-1C3C3C?style=flat-square)](https://langchain-ai.github.io/langgraph/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## Overview

Modern engineering teams ship software quickly, but speed can create security blind spots. Misconfigured Kubernetes workloads, excessive infrastructure permissions, insecure container configurations, and vulnerable deployment workflows can reach production when security checks are disconnected from the release process.

**ACE+RHG moves security enforcement into the release pipeline.**

It consists of two primary components:

- **ACE (AI Compliance Engine):** Scans deployment artifacts using deterministic OPA/Rego policy bundles, identifies compliance violations, evaluates risk, and uses an agentic reasoning layer to understand findings and plan context-aware remediation.
- **RHG (Release Hardening Gate):** Enforces release decisions. It coordinates remediation, validates proposed changes, re-scans artifacts, and determines whether a release should be allowed, patched, or blocked.

The platform combines policy-as-code with agentic AI while keeping security enforcement deterministic.

### How it works

```text
Developer Push / Pull Request
             |
             v
          CI/CD
             |
             v
     Release Hardening Gate
             |
             v
       ACE Compliance Engine
             |
      +------+------+
      |             |
      v             v
   OPA/Rego     Backend Scanner
      |             |
      +------+------+
             |
             v
      Security Findings
             |
             v
    LangGraph Agent Workflow
             |
      +------+------+ 
      |             |
      v             v
 Context Agent   Remediation Agent
                    |
                    v
                PatchEngine
                    |
                    v
          Compatibility Check
                    |
                    v
            Verification Agent
                    |
                    v
              OPA Re-scan
                    |
                    v
             Final RHG Decision
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
      ALLOW       PATCHED      BLOCK
        |           |           |
        +-----------+-----------+
                    |
                    v
          CI/CD Status + Audit
```

---

## Core capabilities

| Capability | Description |
|---|---|
| Policy-as-Code | Deterministic security enforcement using OPA and Rego |
| Multi-artifact scanning | Scans Kubernetes, Terraform, Dockerfiles, Helm, GitHub Actions, and Docker Compose |
| Agentic remediation | Uses LangGraph agents and NVIDIA Nemotron to reason about findings and propose fixes |
| Automated patching | Applies structured JSON Patch operations through the PatchEngine |
| Compatibility verification | Checks whether proposed changes remain compatible with backend application requirements |
| Risk scoring | Assigns severity and risk scores to compliance findings |
| Release enforcement | Returns ALLOW, PATCHED, or BLOCK decisions |
| Human-in-the-loop | Escalates uncertain or unsafe remediation cases for human review |
| CI/CD integration | Supports pipeline-based scanning and release gating |
| Auditability | Tracks policy findings, remediation proposals, mutations, verification, and release decisions |
| Notifications | Routes mutation and release events through supported notification channels |

---

## Agentic AI architecture

ACE+RHG extends traditional policy-based scanning with a LangGraph-powered agentic release workflow.

### Specialized agents

**1. Context Agent**

- Understands the deployment artifact and application context.
- Interprets OPA findings and their potential impact.
- Uses backend scan information to understand application dependencies.
- Provides context to the remediation workflow.

**2. Remediation Agent**

- Evaluates policy findings and contextual information.
- Proposes safe remediation strategies.
- Produces structured JSON Patch operations.
- Provides reasoning, confidence, and escalation information.

**3. Verification Agent**

- Interprets the results of policy rescanning and compatibility checks.
- Determines whether the remediation resolved the original violation.
- Supports bounded retry workflows.
- Escalates unresolved or unsafe cases.

### Agentic release lifecycle

```text
Analyze Findings
       |
       v
Understand Context
       |
       v
Plan Remediation
       |
       v
Apply JSON Patch
       |
       v
Compatibility Check
       |
       v
Verify Remediation
       |
       +-------> Retry if safe and permitted
       |
       v
OPA Re-scan
       |
       v
Final Release Decision
```

### NVIDIA Nemotron + Nebius Token Factory

NVIDIA Nemotron serves as the reasoning layer in the agentic workflow, accessed through Nebius Token Factory.

We use the model to:

- Interpret structured security and compliance findings.
- Understand the context behind deployment misconfigurations.
- Generate remediation plans based on policy findings.
- Produce structured outputs for downstream workflow stages.
- Assist verification agents in interpreting remediation results.

The model is integrated through an LLM provider abstraction, allowing the application to switch between supported inference providers without tightly coupling the agent orchestration layer to one provider.

**Model configuration**

| Setting | Configuration |
|---|---|
| Primary provider | Nebius Token Factory |
| Provider implementation | `ace.llm.LLMProvider` |
| Model configuration | `NEMOTRON_MODEL` |
| Default model ID | `nvidia/nemotron-3-super-120b-a12b` |
| API endpoint | `https://api.studio.nebius.ai/v1` |
| Orchestration | LangGraph |

The architecture deliberately separates AI reasoning from security authority:

- OPA remains the sole authority for policy evaluation.
- Nemotron reasons about findings and proposes remediation.
- PatchEngine is responsible for applying artifact mutations.
- Compatibility checks validate proposed changes.
- RHG makes the final release decision.

**AI proposes. Deterministic systems validate and enforce.**

---

## Quick Start

ACE+RHG can run against either a locally hosted Docker Compose stack or a deployed backend.

### Prerequisites

- Python 3.12+
- Docker and Docker Compose
- Git
- OPA CLI for local policy development
- Nebius Token Factory API key for agentic inference

### Option 1: Cloud

Install the CLI:

```bash
pip install ace-compliance
```

Configure the cloud endpoints:

```bash
export ACE_URL=https://fw6mh9jzpc.execute-api.ap-south-1.amazonaws.com
export RHG_URL=https://fw6mh9jzpc.execute-api.ap-south-1.amazonaws.com
```

Configure authentication:

```bash
export ACE_API_KEY=ace_sk_...
```

Initialize an organization and project:

```bash
ace create-org myorg

ace add-repo myorg myapp \
  --repo owner/repo

ace gen-key myorg myapp \
  --scopes scan,submit
```

Scan deployment artifacts:

```bash
ace scan ./manifests
```

Submit artifacts to the release gate:

```bash
ace submit ./manifests \
  --repo owner/repo \
  --branch main \
  --env prod \
  --fail-on HIGH
```

View recent activity:

```bash
ace history --limit 10
```

### Option 2: Local development

Clone the repository:

```bash
git clone https://github.com/omkarP-bit/AI-Compliance-Engine-RHG.git

cd AI-Compliance-Engine-RHG
```

Start the local services:

```bash
docker-compose up -d
```

The local stack includes:

| Service | Endpoint |
|---|---|
| ACE API | http://localhost:8000 |
| RHG API | http://localhost:8001 |
| OPA | http://localhost:8181 |
| Redis | localhost:6390 |
| Prometheus | Local monitoring service |
| Grafana | Local dashboard service |

Run a compliance scan:

```bash
ace scan ./samples --profile local
```

Submit an artifact for release evaluation:

```bash
ace submit ./samples/vulnerable-deploy.yaml \
  --profile local \
  --repo test/repo \
  --fail-on HIGH
```

Run the agentic workflow:

```bash
ace agent ./samples --profile local
```

Stop the services:

```bash
docker-compose down
```

For agentic inference, configure your Nebius credentials:

```bash
export MODEL_PROVIDER=nebius
export NEBIUS_API_KEY=your_api_key
export NEMOTRON_MODEL=nvidia/nemotron-3-super-120b-a12b
```

Never commit API keys or other secrets to the repository.

---

## CLI Reference

### Setup and authentication

| Command | Description |
|---|---|
| `ace init` | Display the initial setup guide |
| `ace create-org <org>` | Create an organization |
| `ace add-repo <org> <project>` | Link a repository to a project |
| `ace gen-key <org> <project>` | Generate an API key |
| `ace login --api-key <key>` | Save credentials locally |
| `ace whoami` | Display active credentials |
| `ace logout` | Remove saved credentials |

### Scanning and release gating

| Command | Description |
|---|---|
| `ace scan <paths...>` | Scan artifacts for compliance violations |
| `ace mutate <path>` | Generate RFC 6902 patches |
| `ace scan-and-mutate <paths...>` | Scan artifacts and generate patches |
| `ace submit <paths...>` | Execute the release-gating workflow |
| `ace agent <paths...>` | Run the agentic remediation workflow |
| `ace history` | View merged Git and ACE activity |

#### Infra vs backend scans

`--infra` and `--backend` are separate modes, so results never mix:

* `ace scan --infra` scans only infrastructure/config artifacts (Kubernetes,
  Helm, Terraform YAML, compose files and Dockerfiles).
* `ace scan --backend` scans only application source code and reports API
  findings with `file:line` and code snippets. Positional paths given with
  `--backend` are treated as source roots.
* Without either flag, `ace scan` scans config artifacts in the given paths.

### Utilities

| Command | Description |
|---|---|
| `ace health` | Check service health |
| `ace config` | Display resolved configuration |

### Global options

```text
--profile [local|cloud|auto]
--ace-url
--rhg-url
--timeout
--output [text|json]
-q / --quiet
-v / --verbose
```

---

## Supported artifacts

| Artifact | Supported formats | Policy coverage |
|---|---|---|
| Kubernetes | `.yaml`, `.yml` | CIS Kubernetes |
| Terraform | `.tf`, `.tf.json`, plans | CIS Terraform |
| Dockerfiles | `Dockerfile`, `*.dockerfile` | CIS Docker |
| Helm | YAML templates | CIS Kubernetes |
| GitHub Actions | Workflow YAML | GitHub Actions Security |
| Docker Compose | Compose YAML | CIS Docker Compose |

Directory scanning recursively discovers supported artifact files.

Backend source analysis can also provide application context for compatibility checks. Sensitive `.env` files are excluded from backend analysis and are never submitted as backend source.

---

## Compliance standards

ACE uses OPA/Rego policy bundles to evaluate deployment artifacts against security and compliance requirements.

| Standard / Policy | Example coverage |
|---|---|
| CIS Kubernetes Benchmark v1.8 | Privileged containers, root execution, resource limits, host networking, privilege escalation |
| CIS Docker Benchmark v1.6 | Root execution, missing HEALTHCHECK |
| CIS Terraform Benchmark | Infrastructure configuration and security checks |
| NIST SP 800-53 Rev. 5 | Least privilege, configuration management, system integrity |
| GitHub Actions Security | Excessive permissions, mutable action references, unsafe workflow triggers, script injection |
| Custom Rego policies | Organization-specific compliance requirements |

---

## Release decisions

RHG evaluates the results of scanning, remediation, compatibility verification, and policy rescanning.

| Decision | Meaning |
|---|---|
| `ALLOW` | No blocking policy violations remain |
| `PATCHED` | Remediation was applied and successfully verified |
| `BLOCK` | Unresolved, unsafe, or blocking violations prevent release |

A model-generated suggestion cannot override an OPA policy decision or an incompatible verification result.

When the system cannot establish a safe remediation, it can escalate the finding for human review rather than silently applying an uncertain change.

---

## Cloud deployment

The existing cloud backend uses AWS managed infrastructure.

### Deployment architecture

```text
Developer / CI/CD
       |
       | HTTPS
       v
   API Gateway v2
       |
       | Lambda Proxy
       v
   AWS Lambda
   FastAPI + Mangum
       |
       +-----------> OPA
       |              ECS Fargate
       |
       +-----------> SQS FIFO
       |
       +-----------> Storage
                      DynamoDB
```

### AWS infrastructure

| Resource | Purpose |
|---|---|
| API Gateway v2 | HTTPS API entry point |
| AWS Lambda | Serverless ACE API and dispatcher |
| Amazon ECR | Container image registry |
| Amazon ECS Fargate | OPA policy engine hosting |
| Amazon SQS FIFO | Alert and event dispatch |
| DynamoDB | Cloud metadata storage |
| CloudWatch EMF | Cloud metrics and monitoring |

The local development environment uses PostgreSQL, while the cloud architecture uses DynamoDB for metadata storage.

The scan Lambda communicates with OPA through the configured `OPA_URL`. OPA runs as a separate ECS Fargate service rather than inside the Lambda container.

### API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Service health check |
| POST | `/ace/scan` | Scan deployment artifacts |
| POST | `/ace/mutate` | Generate remediation patches |
| POST | `/ace/scan-and-mutate` | Scan and generate patches |
| POST | `/ace/agent` | Run the ACE agentic workflow |
| POST | `/rhg/agentic-submit` | Execute the agentic release gate |

**Deployment note:** The published AWS scan deployment and the complete v3 agentic deployment are separate deployment concerns. Verify that the hosted environment exposes the v3 routes before using `ace agent` against the cloud profile.

---

## CI/CD integration

ACE+RHG is designed to integrate into existing developer workflows.

### GitHub Actions

```yaml
name: ACE Compliance Gate

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install ACE
        run: pip install ace-compliance

      - name: Run Compliance Scan
        run: |
          ace scan ./k8s ./terraform \
            --output json \
            --fail-on HIGH

        env:
          ACE_URL: ${{ secrets.ACE_URL }}
          ACE_API_KEY: ${{ secrets.ACE_API_KEY }}
```

The CLI exit status can be used to fail a pipeline when the configured severity threshold is reached.

Additional integration targets include GitLab CI, Jenkins, and ArgoCD.

---

## Observability and notifications

The platform supports operational visibility through:

- **Redis Pub/Sub:** Internal event distribution.
- **WebSockets:** Live event updates to connected clients.
- **Prometheus:** Local metrics collection.
- **Grafana:** Local monitoring dashboards.
- **CloudWatch EMF:** Cloud metrics from the Lambda functions (`ACE-RHG`
  namespace), viewable in the native CloudWatch dashboard
  (`ACE-RHG-Overview`) or in Grafana Cloud through the CloudWatch data source.
- **Slack:** Mutation and operational notifications.
- **AWS SQS FIFO:** Asynchronous alert dispatch.

The same metric names are used in both environments; see
[`infra/observability/README.md`](infra/observability/README.md) for the metric
catalogue, the CloudWatch dashboard deploy command and Grafana Cloud setup.

Important events include scan completion, mutation application, compatibility results, gate decisions, and agent workflow events.

---

## Security principles

ACE+RHG is designed around a few important security boundaries:

1. **Deterministic policy authority:** OPA is the sole authority for security policy evaluation.
2. **Restricted AI responsibilities:** Nemotron reasons about findings and proposes remediations; it cannot override policy decisions.
3. **Controlled mutation:** Only the PatchEngine applies structured JSON Patch operations.
4. **Compatibility validation:** Proposed changes must pass compatibility checks.
5. **Verification before release:** Patched artifacts are rescanned against policy.
6. **Human oversight:** Uncertain or unsafe remediation cases can be escalated.
7. **Secret protection:** `.env` files are excluded from backend source analysis and are never submitted as backend source.
8. **Fail-closed agentic behavior:** If the required inference configuration is unavailable, the agentic workflow fails closed rather than shipping unreviewed changes.

---

## Tech stack

| Layer | Technologies |
|---|---|
| Backend | Python 3.12, FastAPI, Pydantic |
| Policy engine | Open Policy Agent, Rego |
| Agent orchestration | LangGraph |
| AI inference | NVIDIA Nemotron, Nebius Token Factory |
| Alternative model provider | Groq Llama 3.3 70B |
| LLM integration | `ace.llm.LLMProvider` |
| Tool integration | Model Context Protocol (MCP) |
| Mutation engine | JSON Patch, RFC 6902 |
| CLI | Click, httpx, PyYAML |
| Event bus | Redis Pub/Sub, WebSockets |
| Local storage | PostgreSQL |
| Cloud storage | DynamoDB |
| Cloud infrastructure | AWS Lambda, API Gateway v2, ECR, ECS Fargate, SQS |
| Monitoring | Prometheus, Grafana, CloudWatch EMF |
| Containers | Docker, Docker Compose |
| Infrastructure artifacts | Kubernetes, Terraform, Helm |
| CI/CD | GitHub Actions, GitLab CI, Jenkins, ArgoCD |

---

## Testing

ACE+RHG includes automated test coverage across its primary services and CLI.

Run the test suite:

```bash
make test
```

Run linting:

```bash
make lint
```

The current documented test suite contains **355 passing tests**.

Tests cover areas including:

- Artifact parsing and normalization.
- OPA policy evaluation.
- Scan and mutation APIs.
- LLM provider abstraction.
- Agent workflow and state contracts.
- Release-gating logic.
- Compatibility checks.
- CLI commands.
- Cloud handler behavior.

---

## Repository structure

```text
AI-Compliance-Engine-RHG/
│
├── README.md
├── CLAUDE.md
├── DEVELOPMENT.md
├── LICENSE
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── requirements-dev.txt
│
├── services/
│   ├── ace/
│   │   ├── api/
│   │   ├── agents/
│   │   ├── llm/
│   │   ├── parsers/
│   │   ├── engine/
│   │   ├── mutator/
│   │   ├── scoring/
│   │   ├── alerts/
│   │   ├── mcp/
│   │   └── tests/
│   │
│   └── rhg/
│       ├── api/
│       ├── gate/
│       ├── mutator/
│       └── tests/
│
├── policies/
│   ├── cis-kubernetes/
│   ├── cis-docker/
│   ├── cis-docker-compose/
│   ├── cis-terraform/
│   ├── nist-800-53/
│   ├── github-actions/
│   └── custom/
│
├── cli/
│   ├── ace_compliance/
│   └── tests/
│
├── plugins/
│   ├── github-actions/
│   ├── gitlab/
│   ├── jenkins/
│   └── argocd/
│
├── infra/
│   ├── helm/
│   ├── docker/
│   ├── aws_lambda/
│   └── observability/
│
└── samples/
```

---

## Roadmap

Potential areas for further development include:

- Expanded policy coverage for additional cloud providers and infrastructure tools.
- Additional specialized security agents.
- Improved cross-artifact risk correlation.
- More extensive remediation evaluation and benchmarking.
- Expanded CI/CD integrations.
- Deeper audit and observability capabilities.

---

## Contributing

Contributions are welcome.

```bash
git clone https://github.com/omkarP-bit/AI-Compliance-Engine-RHG.git

cd AI-Compliance-Engine-RHG

python -m venv .venv

source .venv/bin/activate

pip install -r requirements-dev.txt
```

Areas where contributions are useful:

- New OPA/Rego policy bundles.
- Additional artifact parsers.
- New agent specializations.
- Cloud provider support for GCP and Azure.
- CI/CD integrations.
- Test coverage and documentation improvements.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

**Built with by Omkar Patil**

*Shift security left. Ship with confidence.*