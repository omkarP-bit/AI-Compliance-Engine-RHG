"""``ace agent`` — run the v3 agentic release loop from the CLI.

``ace scan`` only reports findings; ``ace agent`` drives the full ACE agent
loop: parse -> OPA evaluate -> reason -> remediate through ``PatchEngine`` ->
compatibility gate -> ALLOW/PATCHED/BLOCK. It reaches the work over the same
HTTP boundary as every other client.

By default it calls ACE directly (``POST /ace/agent``). Pass ``--via rhg`` to
route through RHG's ``POST /rhg/agentic-submit`` proxy, which additionally
records the gate metric and dispatches the ``gate.decision`` alert.

Exit code is non-zero when the gate blocks, when the residual severity meets
``--fail-on``, or (with ``--fail-on-escalation``) when the loop escalates.
"""

from __future__ import annotations

import asyncio
import json

import click
import httpx

from ace_compliance.config import EndpointError, resolve_ace_url, resolve_rhg_url
from ace_compliance.helpers import (
    PROFILE_CHOICES,
    SEVERITY_CHOICES,
    SEVERITY_ORDER,
    collect_artifacts,
    collect_backend,
    pick,
)


@click.command(name="agent")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--env", default="production", help="Target environment")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (overrides the group default)")
@click.option("--fail-on", type=click.Choice(SEVERITY_CHOICES), default="HIGH",
              help="Exit non-zero when residual severity is at least this level")
@click.option("--fail-on-escalation", is_flag=True, default=False,
              help="Exit non-zero when the loop escalates to a human")
@click.option("--via", type=click.Choice(["ace", "rhg"]), default="ace",
              help="Call ACE /ace/agent directly (default) or the RHG /rhg/agentic-submit proxy")
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE", help="Deployment profile (overrides the group default)")
@click.option("--ace-url", default=None, help="ACE service URL (overrides the profile; used with --via ace)")
@click.option("--rhg-url", default=None, help="RHG service URL (overrides the profile; used with --via rhg)")
@click.option("--timeout", type=float, default=None, help="Request timeout in seconds (default 300)")
@click.option("--backend-path", multiple=True, type=click.Path(exists=True),
              help="Backend source file or directory to analyze (repeatable; .env is never sent)")
@click.option("--repo", default="unknown/repo", show_default=True,
              help="Repository slug (only sent with --via rhg)")
@click.option("--branch", default="main", show_default=True,
              help="Branch name (only sent with --via rhg)")
@click.option("--model-provider", default=None, help="Override the LLM provider the agents use (ACE only)")
@click.option("--max-retries", type=int, default=None, help="Max remediation retries per finding (ACE only)")
@click.option("--confidence-threshold", type=float, default=None,
              help="Minimum agent confidence to patch without escalating (ACE only)")
@click.option("--block-on-severity", type=click.Choice(SEVERITY_CHOICES), default=None,
              help="Severity at/above which a finding blocks the release (ACE only)")
@click.pass_context
def agent(ctx, paths, env, output, fail_on, fail_on_escalation, profile, via, ace_url, rhg_url,
          timeout, backend_path, repo, branch, model_provider, max_retries,
          confidence_threshold, block_on_severity):
    """Scan artifacts and run the agentic remediation loop."""
    g = ctx.obj
    output = pick(output, g.output, default="text")
    timeout = pick(timeout, g.timeout, default=300.0)

    if not paths:
        paths = (".",)

    artifacts = collect_artifacts(paths)
    if not artifacts:
        click.echo("No supported artifacts found.", err=True)
        raise SystemExit(1)

    backend_source = collect_backend(backend_path)

    try:
        base_url = resolve_rhg_url(pick(profile, g.profile), pick(rhg_url, g.rhg_url)) if via == "rhg" \
            else resolve_ace_url(pick(profile, g.profile), pick(ace_url, g.ace_url))
    except EndpointError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(2)

    if via == "rhg":
        if any(v is not None for v in (model_provider, max_retries, confidence_threshold, block_on_severity)):
            click.echo(
                "Warning: --model-provider/--max-retries/--confidence-threshold/--block-on-severity "
                "are ignored with --via rhg.",
                err=True,
            )
        payload = {
            "pipeline_id": "cli-agent",
            "repo": repo,
            "branch": branch,
            "environment": env,
            "artifacts": artifacts,
            "backend_source": backend_source,
        }
        endpoint = "/rhg/agentic-submit"
    else:
        payload = {
            "pipeline_id": "cli-agent",
            "environment": env,
            "artifacts": artifacts,
            "backend_source": backend_source,
        }
        if model_provider:
            payload["model_provider"] = model_provider
        if max_retries is not None:
            payload["max_retries"] = max_retries
        if confidence_threshold is not None:
            payload["confidence_threshold"] = confidence_threshold
        if block_on_severity:
            payload["block_on_severity"] = block_on_severity
        endpoint = "/ace/agent"

    asyncio.run(
        _run_agent(base_url, endpoint, payload, output, fail_on, fail_on_escalation,
                   timeout, g.verbose, g.quiet)
    )


async def _run_agent(base_url, endpoint, payload, output, fail_on, fail_on_escalation,
                     timeout, verbose, quiet):
    url = f"{base_url}{endpoint}"
    async with httpx.AsyncClient() as client:
        if verbose:
            click.echo(f"-> POST {url}", err=True)
        try:
            resp = await client.post(url, json=payload, timeout=timeout)
            resp.raise_for_status()
            result = resp.json()
        except httpx.HTTPStatusError as e:
            click.echo(f"Error: agent request to {url} failed (HTTP {e.response.status_code})", err=True)
            click.echo(e.response.text, err=True)
            if e.response.status_code == 404:
                click.echo(
                    "  Hint: this deployment has no /ace/agent route — it may predate the "
                    "agentic endpoint. Run locally (--profile local) or use --via rhg.",
                    err=True,
                )
            raise SystemExit(1) from e
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            click.echo(f"Error: Cannot connect to agent service at {url}", err=True)
            click.echo("", err=True)
            click.echo("  Make sure the services are running:", err=True)
            click.echo("    docker-compose up -d          # start full stack", err=True)
            click.echo(f"    curl {base_url}/health         # verify it's up", err=True)
            click.echo("", err=True)
            raise SystemExit(1) from e

    if output == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        _print_agent_report(result, quiet=quiet)

    _enforce(result, fail_on, fail_on_escalation)


def _enforce(result: dict, fail_on: str, fail_on_escalation: bool) -> None:
    blocked = result.get("decision") == "BLOCK"
    if fail_on_escalation and result.get("escalated"):
        raise SystemExit(1)
    if blocked:
        raise SystemExit(1)
    overall = result.get("overall_severity")
    if overall is None:
        severities = [
            f.get("severity", "INFO")
            for f in (result.get("blocked_findings") or result.get("blocking_findings") or [])
        ]
        overall = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0), default="INFO")
    if SEVERITY_ORDER.get(overall, 0) >= SEVERITY_ORDER.get(fail_on, 0):
        raise SystemExit(1)


def _print_agent_report(result: dict, quiet: bool = False) -> None:
    decision = result.get("decision", "?")
    if quiet:
        click.echo(
            f"{decision} mutations={result.get('mutations_applied', 0)} "
            f"escalated={'yes' if result.get('escalated') else 'no'}"
        )
        return
    color = {"ALLOW": "green", "PATCHED": "yellow", "BLOCK": "red"}.get(decision, "white")
    click.echo("")
    click.echo("=" * 60)
    click.echo(f"  Decision:      {click.style(decision, fg=color, bold=True)}")
    if "risk_score" in result:
        click.echo(f"  Risk Score:    {result.get('risk_score')}/10")
    if "overall_severity" in result:
        click.echo(f"  Severity:      {result.get('overall_severity')}")
    click.echo(f"  Mutations:     {result.get('mutations_applied', 0)} applied")
    click.echo(f"  Compatibility: {result.get('compatibility_verdict', '?')}")
    click.echo(f"  Escalated:     {'Yes' if result.get('escalated') else 'No'}")
    click.echo("=" * 60)
    if result.get("escalation_reason"):
        click.echo(f"  ! {result['escalation_reason']}")
    blocked = result.get("blocked_findings") or result.get("blocking_findings") or []
    if blocked:
        click.echo("  Blocking findings:")
        for f in blocked:
            click.echo(f"    [{f.get('severity', '?')}] {f.get('rule_id', '?')}  {f.get('message', '')}")
    resolved = result.get("resolved_findings") or []
    if resolved:
        click.echo(f"  Resolved findings: {len(resolved)}")
    click.echo("")
    if result.get("report_url"):
        click.echo(f"  Report: {result['report_url']}")
    click.echo("")
