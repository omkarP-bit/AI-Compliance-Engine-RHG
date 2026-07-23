# ACE+RHG — AI Compliance Engine + Release Hardening Gate

Production-grade DevSecOps platform that enforces security compliance automatically inside CI/CD pipelines — before any artifact ever touches production.

## ace-compliance CLI

```bash
pip install ace-compliance

# Scan a file
ace scan deploy.yaml

# Scan a directory, fail pipeline on HIGH+
ace scan ./k8s/ ./terraform/ --env production --fail-on HIGH

# JSON output for CI integration
ace scan ./artifacts/ --output json
```

The CLI sends artifacts to the ACE service, evaluates them against CIS/NIST/ISO policy bundles via OPA, and returns structured findings with risk scores.

## Quick Start

```bash
# Full local stack
docker compose up -d
ace scan samples/vulnerable-deploy.yaml --env staging
```

## Documentation

- `CLAUDE.md` — full system concept, architecture, API contracts
- `DEVELOPMENT.md` — build guide, phase map, test matrix, Lambda deployment
