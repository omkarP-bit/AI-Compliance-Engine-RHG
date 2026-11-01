# ACE+RHG — developer task runner
#
# Quick start:  make install && make test
# Local stack:  make up   (then `make logs`, `make down`)

SHELL := /bin/bash

ACE := services/ace
RHG := services/rhg
CLI := cli
POLICIES := policies
COMPOSE := docker compose
HELM_CHART := infra/helm/ace-rhg
IMAGE_REPO ?= ace-rhg
IMAGE_TAG ?= 0.1.2
HELM_ARGS ?=

.PHONY: help install test test-ace test-rhg test-cli test-opa coverage \
	lint format scan build publish-test up down logs rebuild ps \
	helm-lint helm-template helm-install helm-uninstall image-service \
	image-lambda image-opa clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- Setup -----------------------------------------------------------------

install: ## Install all dev dependencies + the CLI (editable)
	pip install -r requirements-dev.txt
	pip install -e $(CLI)/

# --- Test ------------------------------------------------------------------

test: ## Run the full Python test suite (ACE + RHG + CLI + Lambda handlers)
	python -m pytest $(ACE)/tests $(RHG)/tests $(CLI)/tests infra/aws_lambda/tests -q

test-ace: ## Run the ACE test suite
	python -m pytest $(ACE)/tests -q

test-rhg: ## Run the RHG test suite
	python -m pytest $(RHG)/tests -q

test-cli: ## Run the CLI test suite
	python -m pytest $(CLI)/tests -q

test-opa: ## Run the OPA policy unit tests
	opa test $(POLICIES)/ -v

coverage: ## Run tests with an ACE coverage report
	python -m pytest $(ACE)/tests \
		--cov=$(ACE) --cov-report=term-missing

# --- Quality ---------------------------------------------------------------

lint: ## Lint with ruff
	ruff check $(ACE) $(RHG) $(CLI)

format: ## Auto-fix and format with ruff
	ruff check --fix $(ACE) $(RHG) $(CLI)
	ruff format $(ACE) $(RHG) $(CLI)

scan: ## Scan the repo with the local ACE CLI
	ace scan . --fail-on HIGH

# --- Build & publish -------------------------------------------------------

build: ## Build the CLI wheel + sdist into cli/dist/
	python -m build $(CLI)/

publish-test: ## Upload the built CLI package to Test PyPI
	twine upload --repository-url https://test.pypi.org/legacy/ $(CLI)/dist/*

image-service: ## Build the combined ACE+RHG service image (Helm runtime)
	docker build -f infra/docker/Dockerfile.service -t $(IMAGE_REPO):$(IMAGE_TAG) .

image-lambda: ## Build the AWS Lambda image (linux/amd64)
	docker build --platform linux/amd64 -f infra/docker/Dockerfile.lambda -t $(IMAGE_REPO)-lambda:$(IMAGE_TAG) .

image-opa: ## Build the OPA policy-server image (linux/amd64)
	docker build --platform linux/amd64 -f infra/docker/Dockerfile.opa -t $(IMAGE_REPO)-opa:$(IMAGE_TAG) .

# --- Local stack -----------------------------------------------------------

up: ## Start the local docker-compose stack
	$(COMPOSE) up -d --build

down: ## Stop the local stack
	$(COMPOSE) down

logs: ## Tail local stack logs
	$(COMPOSE) logs -f --tail=100

rebuild: ## Rebuild the ace + rhg images and restart
	$(COMPOSE) up -d --build ace rhg

ps: ## Show local stack status
	$(COMPOSE) ps

# --- Helm ------------------------------------------------------------------

helm-lint: ## Lint the Helm chart
	helm lint $(HELM_CHART)

helm-template: ## Render the Helm chart locally
	helm template ace-rhg $(HELM_CHART)

helm-install: ## Install/upgrade the chart, bundling the repo's Rego policies
	helm upgrade --install ace-rhg $(HELM_CHART) \
		$(foreach f,$(wildcard $(POLICIES)/*/*.rego),--set-file 'policies.inline.$(subst /,__,$(subst .,\.,$(subst $(POLICIES)/,,$(f))))=$(f)') \
		$(HELM_ARGS)

helm-uninstall: ## Uninstall the chart
	helm uninstall ace-rhg $(HELM_ARGS)

# --- Housekeeping ----------------------------------------------------------

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .coverage coverage.xml htmlcov
	rm -rf $(CLI)/dist $(CLI)/build $(CLI)/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
