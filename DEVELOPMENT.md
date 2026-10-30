# ACE+RHG — Development Status Report

> Generated from full codebase audit against the original DEVELOPMENT.md spec.
> **Tests: 346 passing | Last verified: 2026-10-13**

---

## What's Done (Fully Implemented)

### Phase 1 — Core Engine Foundation ✅

| Component | Status | Notes |
|---|---|---|
| `services/ace/main.py` | ✅ Done | FastAPI app, metrics startup on `@app.on_event("startup")` |
| `services/ace/api/routes.py` | ✅ Done | `/ace/scan`, `/ace/mutate`, `/ace/scan-and-mutate` — more endpoints than spec |
| `services/ace/parsers/base.py` | ✅ Done | `NormalizedArtifact` model, `BaseParser` ABC |
| `services/ace/parsers/kubernetes.py` | ✅ Done | Handles `yaml.safe_load_all`, normalizes deployment/pod specs for OPA |
| `services/ace/parsers/terraform.py` | ✅ Done | Parses `tfplan.json` — resource_changes, filters no-op |
| `services/ace/parsers/dockerfile.py` | ✅ Done | Instruction parser, FROM/USER/EXPOSE/HEALTHCHECK extraction |
| `services/ace/parsers/helm.py` | ✅ Done | Template variable extraction (`{{ .Values.* }}`) — spec addition |
| `services/ace/parsers/github_actions.py` | ✅ Done | `GitHubActionsParser` — write-all perms, mutable tags, `pull_request_target`, script injection, self-hosted runners |
| `policies/github-actions/main.rego` | ✅ Done | 6 GHA-SEC Rego rules (GHA-SEC-001 through GHA-SEC-006) |
| `services/ace/engine/opa_client.py` | ✅ Done | Async HTTP client, `_unwrap_set` for OPA set handling |
| `services/ace/engine/rule_engine.py` | ✅ Done | High-level wrapper with policy map |
| `services/ace/scoring/risk_scorer.py` | ✅ Done | Weighted scoring, env multipliers (prod/staging/dev), capped at 10 |
| `policies/cis-kubernetes/main.rego` | ✅ Done | 6 deny rules + 6 patch rules (privileged, root, CPU/memory limits, privilege escalation, host network) |
| `policies/cis-docker/main.rego` | ✅ Done | 2 deny rules (root user, no HEALTHCHECK) |
| `policies/nist-800-53/main.rego` | ✅ Done | 3 deny rules (AC-6, CM-2, SI-7) with patchable=true |

### Phase 2 — Mutation Engine ✅

| Component | Status | Notes |
|---|---|---|
| `services/rhg/mutator/patch_engine.py` | ✅ Done | RFC 6902 JSON Patch: replace/add/remove, auto-create nested paths, diff engine |
| Tests | ✅ Done | 12 tests covering replace, add, remove, deep copy safety, diff, list indices, missing paths |

### Phase 3 — Agentic AI Layer ✅

| Component | Status | Notes |
|---|---|---|
| `services/ace/agents/base_agent.py` | ✅ Done | `AgentResult` dataclass, `BaseAgent` ABC |
| `services/ace/agents/artifact_agent.py` | ✅ Done | Groq + Llama 3.3 70B (deviation from spec: spec used Anthropic Claude) |
| `services/ace/mcp/tools.py` | ✅ Done | 4 MCP tools: scan_infrastructure, detect_drift, generate_fixes, fetch_cve_data |
| Tests | ✅ Done | 4 tests: empty findings, LLM call, low confidence escalation, malformed response |

### Phase 4 — RHG + CLI ✅

| Component | Status | Notes |
|---|---|---|
| `services/rhg/main.py` | ✅ Done | FastAPI app at port 8001 (spec addition) |
| `services/rhg/api/routes.py` | ✅ Done | Full mutation pipeline: scan → mutate → re-scan → gate decision, max 3 retries |
| `services/rhg/gate/evaluator.py` | ✅ Done | `GateEvaluator` with ALLOW/BLOCK/PATCHED, configurable severity threshold |
| `cli/ace_compliance/cli.py` | ✅ Done | `ace scan` command, text/JSON output, `--fail-on` |
| `cli/pyproject.toml` | ✅ Done | Build config, entry point `ace` |
| `.github/actions/ace-scan/action.yml` | ✅ Done | Composite GitHub Action, installs from local path |
| `.github/workflows/ci.yml` | ✅ Done | 4-jobs: lint (ruff), test (4 suites), build (wheel), publish (PyPI) |
| CLI tests | ✅ Done | 4 tests: exit codes, JSON output, empty dir |
| RHG tests | ✅ Done | 36 tests across gate evaluator, patch engine, helpers, RHG API |

### Phase 5 — Observability ✅

| Component | Status | Notes |
|---|---|---|
| `services/ace/metrics/prometheus.py` | ✅ Done | Counters (scans, findings, mutations, gate decisions), histograms (scan/agent duration), gauges (active scans, OPA health, compliance score) |
| `services/ace/api/websocket.py` | ✅ Done | `ConnectionManager`, Redis Pub/Sub event bus, `/ws/events` endpoint |
| Metrics tests | ✅ Done | 10 tests |
| WebSocket tests | ✅ Done | 7 tests |

### Phase 6 — Alert System ✅

| Component | Status | Notes |
|---|---|---|
| `services/ace/alerts/router.py` | ✅ Done | `AlertRouter` with multi-channel dispatch, `AlertChannel` protocol |
| `services/ace/alerts/channels/slack.py` | ✅ Done | Block Kit formatting, color-coded by decision (green/red/amber), severity emoji |
| `services/ace/alerts/channels/sqs.py` | ✅ Done | AWS SQS FIFO, structured message with all fields, MessageAttributes |
| Alert tests | ✅ Done | 7 tests: router dispatch, channel failure resilience, Slack colors, SQS body |

### Phase 7 — Lambda Deployment ✅

| Component | Status | Notes |
|---|---|---|
| `infra/docker/Dockerfile.lambda` | ✅ Done | Lambda Python 3.12 base, installs `services/ace/requirements.txt`; bundles code as `./ace/`, policies as `./ace/policies/` (no OPA binary) |
| `services/ace/lambda_handler.py` | ✅ Done | Scan entrypoint: `handler = Mangum(app, lifespan="off")`; calls remote OPA via `OPA_URL` |
| `infra/aws_lambda/handlers/alert_dispatcher_handler.py` | ✅ Done | SQS-triggered; fans out via `build_alert_router()` |
| OPA runtime (`ace-opa-dev`) | ✅ Done | OPA + Rego bundles image in ECR `ace-opa-dev:latest`; standalone ECS Fargate service (public IP, no ALB/NAT), provisioned ad-hoc via AWS CLI (no Terraform/scripts in repo); scan Lambda `OPA_URL` points at the task public IP |
| Lambda tests | ✅ Done | `infra/aws_lambda/tests/` — SQS record fan-out + empty event |

### Phase 11 — LLM Provider Abstraction (Nebius / Nemotron) ✅

| Component | Status | Notes |
|---|---|---|
| `services/ace/llm/base.py` | ✅ Done | `LLMMessage`/`LLMResponse` dataclasses, `LLMProvider` ABC with `provider_name`, `model_name`, `complete()` |
| `services/ace/llm/nebius.py` | ✅ Done | NVIDIA Nemotron over Nebius Token Factory's OpenAI-compatible `/v1/chat/completions`; no Nebius SDK needed |
| `services/ace/llm/provider.py` | ✅ Done | `get_provider()` factory keyed on `MODEL_PROVIDER`, `supported_providers()` |
| Tests | ✅ Done | 11 tests: missing key, bearer header, base-URL/model overrides, usage parsing, factory errors |

`NebiusProvider.__init__` never raises on a missing key. Agents are constructed at
import time in several modules, so a hard `KeyError` there would take down the
whole service in deployments that do not use agentic mode. The error is deferred
to `complete()`, where it is actionable (`NebiusConfigurationError`).

### Phase 12 — LangGraph Agentic Release Loop ✅

| Component | Status | Notes |
|---|---|---|
| `services/ace/agents/state.py` | ✅ Done | `AgentState` TypedDict, reducer-backed audit/result lists, `initial_state()`, `should_block()` |
| `services/ace/agents/context_agent.py` | ✅ Done | Explains *why* a finding matters; never decides policy |
| `services/ace/agents/remediation_agent.py` | ✅ Done | Proposes PATCH/SKIP/ESCALATE; applies nothing |
| `services/ace/agents/verification_agent.py` | ✅ Done | Interprets re-scan + compatibility verdicts |
| `services/ace/agents/graph.py` | ✅ Done | 8-node state machine: analyzing → reasoning → plan_remediation → mutating → compatibility_check → verification → (retry \| next_finding) → gate |
| `services/ace/engine/artifact_codec.py` | ✅ Done | Parser-aligned decode/encode + `policy_path_for()`; reuses `PARSERS`/`POLICY_MAP` from `api/routes.py` |
| `services/ace/api/compatibility.py` | ✅ Done | Extracted `run_compatibility_check()` so the graph can call it in-process instead of over HTTP |
| `services/ace/mutator/patch_engine.py` | ✅ Done | Moved here from `rhg/`; `rhg/mutator/patch_engine.py` is now a re-export shim |
| Tests | ✅ Done | 28 agent/state unit tests + 37 graph integration tests |

**Deviations from the Phase 12 sketch, all deliberate:**

| Sketch said | Actual | Why |
|---|---|---|
| `AgentState` as a `@dataclass` | `TypedDict` | LangGraph 1.x passes a *dict* to every node and returns a dict from `ainvoke` even with a dataclass schema, so `result.decision` would raise `AttributeError` |
| Read `state.findings[0]` | Drains a `pending` queue | The sketch silently discarded every finding after the first; a manifest with three violations now gets three remediation cycles |
| Hardcoded `yaml.safe_load`/`yaml.dump` | `artifact_codec` per artifact type | YAML-only mutation corrupts Terraform plan JSON, Dockerfiles and GHA workflows |
| `from ..mutator.patch_engine import PatchEngine` | `ace.mutator.patch_engine` | The engine only existed under `rhg/`; importing it from `ace` was impossible |
| `from ..api.compatibility import run_compatibility_check` | Function now exists | It did not exist — only the HTTP route did |
| Route on `current_state` | Explicit `agent_next_action` field | Overloading `current_state` for routing collided with its use as the audit-trail label |
| `ainvoke(state)` | `run_release_loop(graph, state)` | LangGraph's default 25 super-step limit overflows: each finding costs 5 nodes and each retry 4 more, so a run dies *after* patches are applied. `recursion_config()` sizes the limit |

**Safety invariants (enforced in code, not just in the agent prompts):**

- An `INCOMPATIBLE` compatibility verdict escalates even if the verification
  agent returns `GATE` or `RETRY`. Enforced in `VerificationAgent._parse` *and*
  in the graph — the agent is an untrusted component.
- A `PATCH` plan with an empty `proposed_patches` list is downgraded to
  `ESCALATE`; a no-op must not be reported as a fix.
- A `SKIP` is routed straight past the mutator. Routing it through `mutating`
  would apply an empty patch list and report the artifact as patched.
- Low confidence, `requires_human_review`, a retry that is unsafe or out of
  budget, a missing artifact, an undecodable artifact, a malformed JSON pointer,
  and any OPA outage during re-scan all fail **closed** to `BLOCK`.
- Without `NEBIUS_API_KEY`, agentic runs fail closed to `BLOCK` rather than
  shipping unreviewed patches.

### Phase 13 — HTTP Agent Endpoints + `ace agent` ✅

| Component | Status | Notes |
|---|---|---|
| `services/ace/api/agent_routes.py` | ✅ Done | `POST /ace/agent` — drives the v3 loop and returns decision, findings, patched artifacts, audit trail, `report_url` |
| `services/rhg/api/agentic_routes.py` | ✅ Done | `POST /rhg/agentic-submit` — proxies `/ace/agent`, then dispatches the `gate.decision` alert |
| `cli/ace_compliance/agent_cli.py` | ✅ Done | `ace agent` with `--via [ace\|rhg]`, `--profile`, `--fail-on`, `--fail-on-escalation`, `--backend-path` |
| `services/rhg/api/routes.py` | ✅ Done | Gate alert dispatch (`_dispatch_alert`) via `AlertRouter` |

### Phase 14 — CI/CD Plugin Expansion ✅

| Component | Status | Notes |
|---|---|---|
| `plugins/github-actions/` | ✅ Done | npm action (`package.json`, `src/index.js`, `src/lib.js`) + tests |
| `plugins/gitlab/` | ✅ Done | `.gitlab/components/ace-gate.yml` CI component |
| `plugins/jenkins/` | ✅ Done | `vars/aceGate.groovy` shared-library step |
| `plugins/argocd/` | ✅ Done | `Application` + `PreSync` gate Job |

### Phase 15 — Packaging, Docs & Deployment Polish ✅

| Component | Status | Notes |
|---|---|---|
| `CLAUDE.md` | ✅ Done | Architecture reference |
| `Makefile` | ✅ Done | install/test/lint/opa/build/up/down/helm targets |
| `LICENSE` | ✅ Done | MIT |
| `.pre-commit-config.yaml` | ✅ Done | ruff, yaml/json checks, OPA + ACE local hooks |
| `requirements-dev.txt` | ✅ Done | Dev + service deps in one install |
| `policies/custom/` | ✅ Done | Template bundle + docs (not wired into `POLICY_MAP`) |
| `infra/helm/ace-rhg/` | ✅ Done | Helm chart (ACE, RHG, OPA, Redis, policies, secret, ingress) |
| `infra/docker/Dockerfile.service` | ✅ Done | Combined ACE+RHG runtime image for Helm |

### Samples

| File | Status |
|---|---|
| `samples/vulnerable-deploy.yaml` | ✅ Done | K8s Deployment (privileged, root) + Pod (safe) |
| `samples/main.tf` | ✅ Done | Terraform: AWS instance + S3 bucket |
| `samples/Dockerfile` | ✅ Done | `ubuntu:latest`, no USER |

### CI/CD

| Component | Status |
|---|---|
| `.github/workflows/ci.yml` | ✅ Done | Lint (ruff), test (4 suites), build wheel/sdist, publish to Test PyPI / PyPI |
| `.github/actions/ace-scan/action.yml` | ✅ Done | Composite action for pipeline integration |

### Docker Compose

| Service | Status | Port |
|---|---|---|
| OPA | ✅ Done | 8181 |
| Redis | ✅ Done | 6390 (mapped to 6379) |
| ACE | ✅ Done | 8000 |

---

## What's Missing vs. DEVELOPMENT.md Spec

### Resolved since the previous audit

| Item | Resolution |
|---|---|
| **`CLAUDE.md`** | Added — architecture & contributor reference |
| **`Makefile`** | Added — `install`/`test`/`lint`/`test-opa`/`build`/`up`/`down`/`helm-*` |
| **`.env.example`** | Added (full variable list) |
| **`infra/helm/`** | Added — chart for ACE, RHG, OPA, Redis (+ policies/secret/ingress) |
| **Grafana dashboards** | Added under `infra/observability/grafana/` (file-provisioned) |
| **`policies/custom/`** | Added — template bundle + docs (not yet in `POLICY_MAP`) |
| **`LICENSE`** | Added (MIT) |
| **`requirements-dev.txt`** | Added |
| **`.pre-commit-config.yaml`** | Added |
| **GitLab / Jenkins integrations** | Added under `plugins/` |
| **npm GitHub Action** | Added under `plugins/github-actions/` |
| **RHG + Prometheus + Grafana in compose** | Added (`docker-compose.yml`) |

### Remaining gaps

| Item | Spec Location | Notes |
|---|---|---|
| **React dashboard** (`services/dashboard/`) | Phase 5, README tree | Deliberately out of scope for now — WebSocket and metrics are server-ready but have no UI |

Other items deliberately not added: **PostgreSQL** and **Celery** have no
consumer code (no ORM, no task queue), so adding services for them would be dead
configuration. `DATABASE_URL` appears only as example data scanned by the
backend extractor.

### Spec Deviations (Functional Differences)

| Item | Spec Says | Actual Code | Impact |
|---|---|---|---|
| **LLM provider** | Anthropic Claude (`ChatAnthropic`, `claude-sonnet-4-6`) | Groq (`ChatGroq`, `llama-3.3-70b-versatile`) for the v2 artifact agent, plus a provider abstraction (`ace/llm/`) whose only registered backend is Nebius Token Factory serving NVIDIA Nemotron for the v3 loop | Functional — needs `GROQ_API_KEY` for v2 and `NEBIUS_API_KEY` for v3. Adding a backend means one entry in `ace/llm/provider.PROVIDERS` |
| **Terraform policy bundle** | `policies/cis-terraform/main.rego` referenced via `POLICY_MAP` | `policies/cis-terraform/` **now exists** and `opa test policies/` passes | Resolved — Terraform scans are no longer a silent no-op |
| **FastAPI event handler** | Not mentioned | Uses deprecated `@app.on_event("startup")` instead of lifespan | Works but shows deprecation warning in test output |
| **OPA health exception handling** | Catches `Exception` | Catches `httpx.RequestError, httpx.HTTPStatusError` | More specific, better practice |
| **Slack emoji** | Has emoji in decision labels (`✅`, `🚫`, `🔧`) | Decision labels are text-only ("Deployment allowed") | Slightly less visual — emoji still in header via `SEVERITY_EMOJI` |
| **Alert router exception** | Catches generic `Exception` | Catches `ConnectionError, TimeoutError, OSError` | More specific |
| **SQS client init** | Direct instantiation | Lazy `@property` pattern | Better for Lambda cold starts |
| **OPA client `_unwrap_set`** | Not mentioned | Handles OPA's set serialization | Required for real OPA responses |
| **K8s parser normalization** | Simple `.raw` passthrough | `_normalize_for_opa` flattens template spec for deployment kinds | Required for correct OPA evaluation |

### Minor Gaps

| Item | Notes |
|---|---|
| **`docker-compose.yml`** | Now runs OPA, Redis, ACE, RHG, Prometheus, Grafana (Postgres/Celery intentionally omitted — no consumer code) |
| **pre-commit config** | Added (`.pre-commit-config.yaml`) |
| **`requirements-dev.txt`** | Added |
| **npm package** | Added (`plugins/github-actions/`) |
| **GitLab/Jenkins/ArgoCD integrations** | Added under `plugins/` |

### Phase 16 — CLI Control Surface ✅

| Component | Status | Notes |
|---|---|---|
| `cli/ace_compliance/helpers.py` | ✅ Done | Shared `GlobalOptions`/`pick` merging, artifact discovery/encoding, backend-source collection |
| `cli/ace_compliance/cli.py` | ✅ Done | Group-level globals (`--profile/--ace-url/--rhg-url/--timeout/--output/-q/-v`) with per-command override precedence |
| `cli/ace_compliance/service_cli.py` | ✅ Done | `ace health`, `ace config`, `ace mutate`, `ace scan-and-mutate`, `ace submit` (`--write-dir`) mapped to their real endpoints |
| `ace --version` | ✅ Done | Reports the installed `ace-compliance` version via `importlib.metadata` |
| CLI tests | ✅ Done | 19 new tests: health/config/mutate/scan-and-mutate/submit + global-option precedence (CLI total 49) |

---

## Test Results

| Suite | Tests | Status |
|---|---|---|
| ACE (parsers, scorer, OPA client, API, agents, graph, alerts, metrics, websocket, LLM, policies) | 245 | ✅ All pass |
| RHG Gate (evaluator, patch engine, helpers, API, agentic proxy) | 50 | ✅ All pass |
| CLI | 49 | ✅ All pass |
| Lambda handlers (`infra/aws_lambda/tests/`) | 2 | ✅ All pass |
| **Total** | **346** | **✅ 100%** |

`opa test policies/` passes with no failures.

**Coverage:** re-measure with `make coverage` (not tracked in CI gate).

---

## Recommended Next Work

### Deferred / out of scope

- **React dashboard** (`services/dashboard/`) — the only remaining spec item;
  not targeted at this time.

### Optional follow-ups

- Migrate `@app.on_event("startup")` to the lifespan pattern (a deprecation
  warning surfaces in test output).
- Wire the `policies/custom/` bundle into `POLICY_MAP` once real custom rules
  exist.
- Add a PostgreSQL/Celery persistence layer if scan history or async jobs are
  ever needed.
- Publish the Helm chart (chart-releaser) and the CLI to PyPI.
- The live AWS stack (scan + dispatcher Lambdas on ECR `ace-rhg-dev:latest`, SQS
  `ace-alerts-dev.fifo`, shared OPA on the `ace-opa-dev` ECS Fargate service) is
  refreshed ad-hoc via the AWS CLI. The gate alert router currently delivers to
  Slack directly; to move to the decoupled SQS → dispatcher transport, register
  `SQSChannel` in `build_alert_router()` behind a flag (guard against the
  dispatcher re-enqueuing).

---

*ACE+RHG v0.1 — Development Status*
*346 tests passing; phases 1–15 landed. Only the React dashboard remains deferred.*
