"""Integration tests for the LangGraph release-hardening loop.

The agents are stubbed (they have their own unit tests) but the graph, its
routing, the real ``PatchEngine``, the real artifact codec and the real
compatibility checker all run for real. OPA is stubbed at the transport
boundary only.
"""

import base64
import json
from unittest.mock import AsyncMock

import pytest
import yaml

from ace.agents.graph import build_release_graph, recursion_config, run_release_loop
from ace.agents.state import GateDecision, NextAction, Verdict, initial_state
from ace.engine.artifact_codec import decode_content

BACKEND_SCAN = {
    "language": "python",
    "port_bindings": [8000],
    "env_vars_used": ["DATABASE_URL"],
    "routes": ["/health"],
    "frameworks": ["fastapi"],
}

DEPLOY_YAML = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: api:1.0
          securityContext:
            privileged: true
          env:
            - name: DATABASE_URL
              value: postgres://x
"""

FINDING_PRIVILEGED = {
    "rule_id": "CIS-K8S-5.2.1",
    "severity": "HIGH",
    "message": "Privileged container",
    "artifact": "deploy.yaml",
    "patchable": True,
}

FINDING_RUNAS = {
    "rule_id": "CIS-K8S-5.2.8",
    "severity": "MEDIUM",
    "message": "Container runs as root",
    "artifact": "deploy.yaml",
    "patchable": True,
}

# ``/ace/scan`` normalises a Deployment to expose containers at ``spec.containers``
# *as well as* the nested ``spec.template.spec.containers``, and OPA is evaluated
# against that normalised document. Findings therefore point at the flattened path,
# and that is the only path a patch must touch to affect the re-scan.
PRIVILEGED_PATCH = [
    {"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False}
]
RUNAS_PATCH = [
    {"op": "replace", "path": "/spec/containers/0/securityContext/runAsNonRoot", "value": True}
]

PASS = {"verdict": Verdict.PASS, "next_action": NextAction.GATE, "diagnosis": "fixed", "retry_safe": False}


def _b64(content: str) -> str:
    """Artifacts carry base64 bodies, same contract as ``/ace/scan``."""
    return base64.b64encode(content.encode()).decode()


def _artifacts(content=DEPLOY_YAML):
    return [{"type": "kubernetes", "name": "deploy.yaml", "content": _b64(content)}]


def _patched(out, index=0):
    return decode_content(out["patched_artifacts"][index]["content"])


def _plan(patches, action="PATCH", confidence=0.95, review=False, reason="safe"):
    return {
        "action": action,
        "reason": reason,
        "confidence": confidence,
        "requires_human_review": review,
        "proposed_patches": patches,
        "safety_notes": "",
    }


class StubContext:
    name = "stub-context"

    async def analyze(self, state, finding):
        return {
            "what_is_deployed": "prod API",
            "why_violation_matters": finding.get("message", ""),
            "affected_components": ["api"],
            "context_risk_note": "",
        }


class StubRemediation:
    """Yields canned plans in order, repeating the last one forever."""

    name = "stub-remediation"

    def __init__(self, plans):
        self.plans = list(plans)
        self.calls = []

    async def plan(self, finding, context, backend_scan, retry_count=0):
        self.calls.append({"rule_id": finding.get("rule_id"), "retry_count": retry_count})
        return dict(self.plans[min(len(self.calls) - 1, len(self.plans) - 1)])


class StubVerification:
    name = "stub-verification"

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def evaluate(
        self, finding, remediation_plan, rescan_findings, compatibility_result, retry_count, max_retries
    ):
        self.calls.append(
            {
                "rule_id": finding.get("rule_id"),
                "rescan_findings": rescan_findings,
                "compatibility_result": compatibility_result,
                "retry_count": retry_count,
            }
        )
        return dict(self.results[min(len(self.calls) - 1, len(self.results) - 1)])


def _opa(health=True, findings=None, error=None):
    client = AsyncMock()
    client.health = AsyncMock(return_value=health)
    if error is not None:
        client.evaluate_deny = AsyncMock(side_effect=error)
    else:
        client.evaluate_deny = AsyncMock(return_value=list(findings or []))
    return client


def _graph(rem, verif, opa=None, **build_kw):
    return build_release_graph(
        agents={"reasoning": StubContext(), "plan_remediation": rem, "verification": verif},
        opa_client=opa if opa is not None else _opa(),
        **build_kw,
    )


def _state(findings, **kw):
    kw.setdefault("artifacts", _artifacts())
    kw.setdefault("backend_scan", BACKEND_SCAN)
    return initial_state("p-1", findings=findings, **kw)


@pytest.mark.asyncio
class TestReleaseGraphRouting:
    async def test_no_findings_allows_immediately(self):
        rem, verif = StubRemediation([]), StubVerification([])
        out = await run_release_loop(_graph(rem, verif), initial_state("p1", artifacts=_artifacts()))
        assert out["decision"] == GateDecision.ALLOW
        assert out["patches_applied"] == []
        assert rem.calls == [] and verif.calls == []

    async def test_single_finding_is_remediated_and_passes(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.PATCHED
        assert out["verification_result"] == Verdict.PASS
        assert out["escalated"] is False
        assert len(out["patched_artifacts"]) == 1
        assert yaml.safe_load(_patched(out))["spec"]["containers"][0]["securityContext"]["privileged"] is False

    async def test_patch_is_applied_by_the_real_patch_engine(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        applied = [a for a in out["audit_trail"] if a.get("step") == "mutation_applied"]
        assert applied
        assert applied[0]["applied_ops"] == ["replace /spec/containers/0/securityContext/privileged -> False"]

    async def test_both_findings_are_processed_not_just_the_first(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH), _plan(RUNAS_PATCH)])
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED, FINDING_RUNAS])
        )
        assert [c["rule_id"] for c in rem.calls] == ["CIS-K8S-5.2.1", "CIS-K8S-5.2.8"]
        assert out["decision"] == GateDecision.PATCHED
        assert len(out["resolved_findings"]) == 2

    async def test_second_patch_builds_on_the_first(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH), _plan(RUNAS_PATCH)])
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED, FINDING_RUNAS])
        )
        security = yaml.safe_load(_patched(out))["spec"]["containers"][0]["securityContext"]
        assert security["privileged"] is False
        assert security["runAsNonRoot"] is True
        # One entry per artifact, not one per finding.
        assert len(out["patched_artifacts"]) == 1

    async def test_per_finding_state_is_reset_between_findings(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH), _plan(RUNAS_PATCH)])
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED, FINDING_RUNAS])
        )
        assert [a.get("step") for a in out["audit_trail"]].count("next_finding") == 1
        assert out["retry_count"] == 0

    async def test_untouched_artifact_content_is_preserved(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        document = yaml.safe_load(_patched(out))
        assert document["apiVersion"] == "apps/v1"
        assert document["metadata"]["name"] == "api"
        assert document["spec"]["template"]["spec"]["containers"][0]["image"] == "api:1.0"


@pytest.mark.asyncio
class TestReleaseGraphEscalation:
    async def test_low_confidence_blocks_the_release(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH, confidence=0.4)])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK
        assert out["escalated"] is True
        assert "0.40" in out["escalation_reason"]
        assert out["patches_applied"] == []

    async def test_human_review_flag_blocks_the_release(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH, review=True)])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK
        assert out["patched_artifacts"] == []

    async def test_explicit_escalate_action_blocks(self):
        rem = StubRemediation([_plan([], action="ESCALATE", reason="no safe automated fix")])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK
        assert "no safe automated fix" in out["escalation_reason"]

    async def test_blocking_severity_that_is_skipped_blocks(self):
        rem = StubRemediation([_plan([], action="SKIP", reason="needs redesign")])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK

    async def test_non_blocking_skip_is_recorded_as_resolved(self):
        rem = StubRemediation([_plan([], action="SKIP", reason="accepted risk")])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_RUNAS]))
        assert out["decision"] == GateDecision.ALLOW
        assert out["resolved_findings"][0]["skipped"] is True
        # A SKIP must never be routed through the mutator, or it would report a
        # patch that changed nothing.
        assert out["patched_artifacts"] == []
        assert [a.get("step") for a in out["audit_trail"]].count("mutation_applied") == 0

    async def test_missing_artifact_escalates(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        finding = {**FINDING_PRIVILEGED, "artifact": "nope.yaml"}
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([finding]))
        assert out["decision"] == GateDecision.BLOCK
        assert "not submitted" in out["escalation_reason"]

    async def test_finding_without_artifact_reference_escalates(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        finding = {k: v for k, v in FINDING_PRIVILEGED.items() if k != "artifact"}
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([finding]))
        assert out["decision"] == GateDecision.BLOCK
        assert "no artifact reference" in out["escalation_reason"]

    async def test_undecodable_artifact_escalates(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        artifacts = [{"type": "kubernetes", "name": "deploy.yaml", "content": "!!! not base64 !!!"}]
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED], artifacts=artifacts)
        )
        assert out["decision"] == GateDecision.BLOCK
        assert "decode" in out["escalation_reason"]


@pytest.mark.asyncio
class TestReleaseGraphRetries:
    async def test_retry_reapplies_with_incremented_count(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        verif = StubVerification(
            [
                {"verdict": Verdict.FAIL, "next_action": NextAction.RETRY, "diagnosis": "no-op", "retry_safe": True},
                PASS,
            ]
        )
        out = await run_release_loop(
            _graph(rem, verif), _state([FINDING_PRIVILEGED], max_retries=3)
        )
        assert [c["retry_count"] for c in rem.calls] == [0, 1]
        assert out["decision"] == GateDecision.PATCHED
        assert out["retry_count"] == 1

    async def test_retry_stops_at_max_retries(self):
        retry = {
            "verdict": Verdict.FAIL,
            "next_action": NextAction.RETRY,
            "diagnosis": "still broken",
            "retry_safe": True,
        }
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        out = await run_release_loop(
            _graph(rem, StubVerification([retry])), _state([FINDING_PRIVILEGED], max_retries=2)
        )
        # max_retries counts retries *after* the first attempt: 2 retries, 3 plans.
        assert [c["retry_count"] for c in rem.calls] == [0, 1, 2]
        assert out["decision"] == GateDecision.BLOCK
        assert "retry" in out["escalation_reason"].lower()

    async def test_unsafe_retry_is_refused_even_while_retries_remain(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        verif = StubVerification(
            [
                {
                    "verdict": Verdict.FAIL,
                    "next_action": NextAction.RETRY,
                    "diagnosis": "risky",
                    "retry_safe": False,
                }
            ]
        )
        out = await run_release_loop(
            _graph(rem, verif), _state([FINDING_PRIVILEGED], max_retries=5)
        )
        assert len(rem.calls) == 1
        assert out["decision"] == GateDecision.BLOCK

    async def test_escalation_from_verification_blocks(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        verif = StubVerification(
            [
                {
                    "verdict": Verdict.FAIL,
                    "next_action": NextAction.ESCALATE,
                    "diagnosis": "cannot fix automatically",
                    "escalation_reason": "needs a human",
                }
            ]
        )
        out = await run_release_loop(_graph(rem, verif), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK
        assert out["escalation_reason"] == "needs a human"

    async def test_fail_without_escalation_is_left_to_the_gate(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        verif = StubVerification(
            [
                {
                    "verdict": Verdict.FAIL,
                    "next_action": NextAction.GATE,
                    "diagnosis": "unclear",
                    "retry_safe": False,
                }
            ]
        )
        out = await run_release_loop(_graph(rem, verif), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK
        assert out["escalated"] is False
        assert out["blocked_findings"][0]["compatibility_result"] == "COMPATIBLE"


@pytest.mark.asyncio
class TestReleaseGraphCompatibilityAndRescan:
    async def test_incompatible_backend_blocks_even_if_verifier_says_pass(self):
        # Port 9999 is not among the backend's bindings, so the compatibility
        # check escalates. The stub verifier then claims everything is fine —
        # the graph must not take its word for it.
        rem = StubRemediation([_plan([{"op": "replace", "path": "/spec/containers/0/containerPort", "value": 9999}])])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["compatibility_result"] == "INCOMPATIBLE"
        assert out["verification_result"] == Verdict.INCOMPATIBLE
        assert out["decision"] == GateDecision.BLOCK
        assert out["escalated"] is True
        assert "INCOMPATIBLE" in out["escalation_reason"]

    async def test_incompatible_backend_also_blocks_when_the_verifier_asks_to_retry(self):
        rem = StubRemediation([_plan([{"op": "replace", "path": "/spec/containers/0/containerPort", "value": 9999}])])
        verif = StubVerification(
            [{"verdict": Verdict.FAIL, "next_action": NextAction.RETRY, "diagnosis": "retry", "retry_safe": True}]
        )
        out = await run_release_loop(_graph(rem, verif), _state([FINDING_PRIVILEGED], max_retries=3))
        assert len(rem.calls) == 1
        assert out["decision"] == GateDecision.BLOCK

    async def test_malformed_pointer_escalates_instead_of_crashing_the_run(self):
        # PatchEngine converts KeyError/IndexError/TypeError into a
        # create-on-missing fallback but lets ValueError escape. A model can
        # easily propose a name where a list index is required.
        rem = StubRemediation([_plan([{"op": "remove", "path": "/spec/containers/0/env/DATABASE_URL"}])])
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK
        assert "could not be applied" in out["escalation_reason"]
        assert out["patched_artifacts"] == []

    async def test_unknown_probe_path_downgrades_to_needs_review(self):
        rem = StubRemediation(
            [
                _plan(
                    [
                        {
                            "op": "replace",
                            "path": "/spec/containers/0/readinessProbe/httpGet/path",
                            "value": "/readyz",
                        }
                    ]
                )
            ]
        )
        out = await run_release_loop(_graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED]))
        assert out["compatibility_result"] == "NEEDS_REVIEW"
        assert out["decision"] == GateDecision.PATCHED

    async def test_compatibility_is_skipped_without_a_backend_profile(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])), _state([FINDING_PRIVILEGED], backend_scan={})
        )
        assert out["compatibility_result"] == "SKIPPED"
        assert out["decision"] == GateDecision.PATCHED

    async def test_rescan_receives_the_patched_normalised_document(self):
        opa = _opa()
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        await run_release_loop(_graph(rem, StubVerification([PASS]), opa=opa), _state([FINDING_PRIVILEGED]))
        policy, document = opa.evaluate_deny.call_args[0]
        assert policy == "ace/cis/kubernetes"
        assert document["spec"]["containers"][0]["securityContext"]["privileged"] is False

    async def test_opa_outage_during_rescan_blocks_rather_than_pretending_to_pass(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS]), opa=_opa(health=False)), _state([FINDING_PRIVILEGED])
        )
        assert out["decision"] == GateDecision.BLOCK
        assert "OPA" in out["escalation_reason"]
        assert out["verification_result"] != Verdict.PASS

    async def test_opa_error_during_rescan_blocks(self):
        opa = _opa(error=RuntimeError("connection reset"))
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        out = await run_release_loop(_graph(rem, StubVerification([PASS]), opa=opa), _state([FINDING_PRIVILEGED]))
        assert out["decision"] == GateDecision.BLOCK
        assert "connection reset" in out["escalation_reason"]

    async def test_remaining_rescan_findings_are_surfaced_to_the_verifier(self):
        remaining = {**FINDING_PRIVILEGED, "still": True}
        opa = _opa(findings=[remaining])
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        verif = StubVerification([PASS])
        out = await run_release_loop(_graph(rem, verif, opa=opa), _state([FINDING_PRIVILEGED]))
        assert verif.calls[0]["rescan_findings"] == [remaining]
        assert out["last_rescan_findings"] == [remaining]

    async def test_privileged_false_is_visible_at_both_container_paths(self):
        """The K8s parser aliases the flattened and nested container lists.

        ``spec.containers`` and ``spec.template.spec.containers`` hold the *same*
        objects, so a patch applied through either pointer is visible through
        both and the re-scan agrees either way. Worth pinning: if that aliasing
        is ever removed, a patch aimed at the wrong path would silently stop
        clearing the finding, and this test would catch the regression.
        """
        opa = _opa()
        nested = [
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/securityContext/privileged",
                "value": False,
            }
        ]
        rem = StubRemediation([_plan(nested)])
        await run_release_loop(_graph(rem, StubVerification([PASS]), opa=opa), _state([FINDING_PRIVILEGED]))
        rescan_doc = opa.evaluate_deny.call_args[0][1]
        assert rescan_doc["spec"]["containers"][0]["securityContext"]["privileged"] is False
        assert rescan_doc["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is False

    async def test_mutation_does_not_mutate_the_caller_s_artifact(self):
        opa = _opa()
        rem = StubRemediation([_plan(PRIVILEGED_PATCH)])
        state = _state([FINDING_PRIVILEGED])
        await run_release_loop(_graph(rem, StubVerification([PASS]), opa=opa), state)
        # PatchEngine deep-copies, so the submitted artifact must be pristine.
        rescan_doc = opa.evaluate_deny.call_args[0][1]
        assert rescan_doc["spec"]["containers"][0]["securityContext"]["privileged"] is False
        assert state["patched_artifacts"] == []


class TestNonKubernetesArtifacts:
    @pytest.mark.asyncio
    async def test_dockerfile_is_patched_in_its_normalised_form(self):
        dockerfile = "FROM python:3.11\nUSER root\nEXPOSE 8000\n"
        finding = {
            "rule_id": "DOCKER-001",
            "severity": "MEDIUM",
            "message": "Runs as root",
            "artifact": "Dockerfile",
        }
        rem = StubRemediation([_plan([{"op": "replace", "path": "/metadata/user", "value": "appuser"}])])
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])),
            _state(
                [finding],
                artifacts=[{"type": "dockerfile", "name": "Dockerfile", "content": _b64(dockerfile)}],
            ),
        )
        patched = json.loads(_patched(out))
        assert patched["metadata"]["user"] == "appuser"
        # Instructions are the authoritative parse, and must survive the patch.
        assert patched["instructions"] == [
            {"instruction": "FROM", "args": "python:3.11"},
            {"instruction": "USER", "args": "root"},
            {"instruction": "EXPOSE", "args": "8000"},
        ]
        assert patched["metadata"]["exposed_ports"] == ["8000"]

    @pytest.mark.asyncio
    async def test_github_workflow_is_patched_as_yaml(self):
        workflow = {
            "name": "ci",
            "jobs": {"build": {"runs-on": "ubuntu-latest", "permissions": {"contents": "write"}}},
        }
        finding = {
            "rule_id": "GHA-001",
            "severity": "HIGH",
            "message": "Over-permissive workflow token",
            "artifact": ".github/workflows/ci.yml",
        }
        rem = StubRemediation(
            [_plan([{"op": "replace", "path": "/jobs/build/permissions/contents", "value": "read"}])]
        )
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])),
            _state(
                [finding],
                artifacts=[
                    {
                        "type": "github_actions",
                        "name": ".github/workflows/ci.yml",
                        "content": _b64(yaml.safe_dump(workflow)),
                    }
                ],
            ),
        )
        patched = yaml.safe_load(_patched(out))
        assert patched["jobs"]["build"]["permissions"]["contents"] == "read"
        assert patched["name"] == "ci"
        assert patched["jobs"]["build"]["runs-on"] == "ubuntu-latest"

    @pytest.mark.asyncio
    async def test_terraform_plan_json_is_patched_as_json(self):
        plan = {"resource_changes": [{"address": "aws_s3_bucket.b", "change": {"actions": ["create"]}}]}
        finding = {"rule_id": "CIS-TERRAFORM-1", "severity": "MEDIUM", "message": "No encryption", "artifact": "plan.json"}
        rem = StubRemediation(
            [_plan([{"op": "replace", "path": "/resource_changes/0/change/actions", "value": ["delete"]}])]
        )
        out = await run_release_loop(
            _graph(rem, StubVerification([PASS])),
            _state(
                [finding],
                artifacts=[{"type": "terraform", "name": "plan.json", "content": _b64(json.dumps(plan))}],
            ),
        )
        patched = json.loads(_patched(out))
        assert patched["resource_changes"][0]["change"]["actions"] == ["delete"]
        assert patched["resource_changes"][0]["address"] == "aws_s3_bucket.b"


class TestRecursionConfig:
    def test_limit_scales_with_findings_and_retries(self):
        assert recursion_config({"findings": [1] * 3, "max_retries": 3})["recursion_limit"] > 25

    def test_limit_has_a_floor_for_empty_state(self):
        assert recursion_config({})["recursion_limit"] > 0

    @pytest.mark.asyncio
    async def test_sized_limit_completes_a_run_the_default_limit_would_truncate(self):
        rem = StubRemediation([_plan(PRIVILEGED_PATCH), _plan(RUNAS_PATCH)])
        state = _state([FINDING_PRIVILEGED, FINDING_RUNAS], max_retries=3)
        # LangGraph's stock limit is 25 super-steps; two findings plus retry
        # headroom exceeds it, so the graph must be driven with a sized config.
        assert recursion_config(state)["recursion_limit"] > 25
        out = await _graph(rem, StubVerification([PASS])).ainvoke(
            state, config=recursion_config(state)
        )
        assert out["decision"] == GateDecision.PATCHED
        assert len(out["resolved_findings"]) == 2
