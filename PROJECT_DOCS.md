# ACE+RHG - Complete Technical Documentation

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Components](#components)
3. [Policy Engine](#policy-engine)
4. [CLI Architecture](#cli-architecture)
5. [Authentication & Orgs](#authentication--orgs)
6. [Storage Layer](#storage-layer)
7. [Metrics & Observability](#metrics--observability)
8. [Deployment](#deployment)
9. [API Reference](#api-reference)
10. [Development](#development)

## Architecture Overview

ACE+RHG implements a shift-left compliance model. Artifacts flow through ACE for scanning/evaluation against OPA policies, then through RHG for gating decisions with optional auto-remediation.

```
Developer → CLI/CI → RHG Gate → ACE Scan/Mutate → OPA Policies → Decision (ALLOW/PATCHED/BLOCK)
```

## Components

### ACE Service (`services/ace/`)
- **API Routes** (`api/routes.py`): `/ace/scan`, `/ace/mutate`, `/ace/scan-and-mutate`
- **Agent Routes** (`api/agent_routes.py`): Agentic remediation loop
- **Parsers**: Artifact parsing with type detection and normalization
- **OPA Client** (`engine/opa_client.py`): Policy evaluation
- **Agents** (LangGraph): Context, Remediation, Verification agents
- **Scoring**: Risk scoring based on severity and context
- **Mutators**: JSON Patch generation and application

### RHG Service (`services/rhg/`)
- **API Routes** (`api/routes.py`): `/rhg/submit` - orchestrates scan → mutate → gate
- **Agentic Routes** (`api/agentic_routes.py`): `/rhg/agentic-submit`
- **Gate Evaluator** (`gate/evaluator.py`): Decision logic based on severity thresholds
- **Patch Engine** (`mutator/patch_engine.py`): Patch application with retries
- **Compatibility**: Cross-artifact compatibility checks

### CLI (`cli/ace_compliance/`)
- **Core**: Click-based CLI with group options and profile management
- **Commands**: scan, submit, mutate, agent, history, auth, admin
- **Config** (`config.py`): Profile-based endpoint resolution (local/cloud/auto)
- **Helpers**: Artifact collection, path-aware naming

### Common (`services/common/`)
- **Storage**: Abstraction for Postgres/DynamoDB
- **Auth**: API key generation/hashing
- **Metrics**: Client abstraction

## Policy Engine

Policies live in `policies/` as Rego bundles:
- `cis-kubernetes/`: Kubernetes CIS Benchmark
- `cis-terraform/`: Terraform security
- `cis-docker/`: Dockerfile best practices
- `cis-docker-compose/`: Docker Compose security
- `github-actions/`: GitHub Actions security
- `nist-800-53/`: NIST controls
- `custom/`: Custom policies

OPA runs as separate service, policies loaded from bundles.

## CLI Architecture

### Flexible Scanning
- `--all`: Scan all supported artifacts from current directory recursively
- `--infra`: Auto-scan common infra dirs (k8s, infra, manifests, terraform, helm, charts)
- `--backend`: Auto-scan common backend dirs (services, src, app, backend, api, server)
- `--backend-path <path>`: Explicitly include backend source files/dirs (repeatable)

### Profile System
- `local`: Always uses localhost:8000/:8001
- `cloud`: Uses ACE_URL/RHG_URL (required)
- `auto`: Prefers env URLs if set, else local

### Artifact Naming
CLI preserves path context (e.g., `.github/workflows/ci.yml`, `chart/templates/deploy.yaml`) so parsers route correctly.

### Global Options
All commands inherit: `--profile`, `--ace-url`, `--rhg-url`, `--timeout`, `--output`, `-q/--quiet`, `-v/--verbose`

## Authentication & Orgs

### API Keys
- Format: `ace_sk_<32-byte-url-safe>`
- Stored hashed (SHA256) in storage backend
- Shown only once on generation
- Tied to org/project with scopes
- Can be revoked

### Commands
- `ace create-org`: Create organization
- `ace add-repo`: Link project to repo (optional metadata)
- `ace gen-key`: Generate API key
- `ace login`: Save credentials to `~/.config/ace/credentials.json` (0600)

### Storage
Local dev uses `~/.config/ace/local_store.json` with orgs, projects, keys, activity.

## Storage Layer

**Interface** (`services/common/storage/base.py`):
- `record_activity()`, `list_recent_activity()`
- `record_scan_summary()`, `record_gate_decision()`
- Org/project/key CRUD

**Backends**:
- `PostgresStorage`: Local JSON-based store for dev
- `DynamoDBStorage`: Single-table design for cloud (`PK=ACTIVITY#YYYY-MM-DD`, `SK=TS#epoch-ms#<id>`)

**Activity Records** track: event_type, repo, branch, env, severity, findings/mutations counts, gate decision, timestamps. No artifact contents or secrets stored.

## Metrics & Observability

**Interface**: `increment()`, `observe()`, `gauge()`

**Backends**:
- Prometheus (local): Exposes metrics on ports 9090/9091
- CloudWatch EMF (cloud): Logs metrics in Embedded Metric Format

**Key Metrics**: scans_total, findings_total, gate_decisions_total, mutations_total, scan_duration_seconds

## Deployment

### Local (Docker Compose)
Services: ace, rhg, opa, redis, postgres, prometheus, grafana. Run `docker-compose up -d`.

### Cloud (AWS)
- **Compute**: Lambda (container images) for ACE and RHG
- **API Gateway**: HTTP API routing to Lambdas
- **OPA**: ECS Fargate service
- **Storage**: DynamoDB for activity/benchmarks
- **Observability**: CloudWatch Logs/Metrics
- **Alerts**: SQS + Slack webhooks

**Current Cloud**: `https://fw6mh9jzpc.execute-api.ap-south-1.amazonaws.com`

## API Reference

### ACE
- `GET /health` - Health check
- `POST /ace/scan` - Scan artifacts
- `POST /ace/mutate` - Generate patches
- `POST /ace/scan-and-mutate` - Scan + patches
- `POST /ace/agent` - Agentic remediation

### RHG
- `GET /health` - Health check
- `POST /rhg/submit` - Gate submission (orchestrates full flow)
- `POST /rhg/agentic-submit` - Agentic gate submission

## Development

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e cli/

# Test
make test  # 355 tests
make lint  # ruff

# Run locally
docker-compose up -d
```

See DEVELOPMENT.md for detailed development guide.
