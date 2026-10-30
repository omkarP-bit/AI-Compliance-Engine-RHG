"""Service-facing CLI commands: health, config, mutate, scan-and-mutate, submit."""

from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path

import click
import httpx
import yaml

from ace_compliance.config import (
    EndpointError,
    resolve_ace_url,
    resolve_profile,
    resolve_rhg_url,
)
from ace_compliance.helpers import (
    PROFILE_CHOICES,
    SEVERITY_CHOICES,
    SEVERITY_ORDER,
    collect_artifacts,
    collect_backend,
    infer_type,
    pick,
)

ARTIFACT_TYPES = ["kubernetes", "terraform", "dockerfile", "helm", "docker_compose", "github_actions"]


def _resolve_ace(ctx, profile, ace_url):
    g = ctx.obj
    try:
        return resolve_ace_url(pick(profile, g.profile), pick(ace_url, g.ace_url))
    except EndpointError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(2)


def _resolve_rhg(ctx, profile, rhg_url):
    g = ctx.obj
    try:
        return resolve_rhg_url(pick(profile, g.profile), pick(rhg_url, g.rhg_url))
    except EndpointError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(2)


def _timeout(ctx, timeout, default=30.0):
    return pick(timeout, ctx.obj.timeout, default=default)


def _output(ctx, output):
    return pick(output, ctx.obj.output, default="text")


def _load_yaml(path: Path):
    """Return the first mapping document in a (possibly multi-doc) YAML/JSON file."""
    try:
        for doc in yaml.safe_load_all(path.read_text()):
            if isinstance(doc, dict):
                return doc
    except yaml.YAMLError:
        return None
    return None


def _max_severity(findings):
    return max(
        (f.get("severity", "INFO") for f in findings),
        key=lambda s: SEVERITY_ORDER.get(s, 0),
        default="INFO",
    )


def _passes_gate(overall, fail_on):
    return SEVERITY_ORDER.get(overall, 0) >= SEVERITY_ORDER.get(fail_on, 0)


async def _post_json(base_url, path, payload, timeout, verbose):
    url = f"{base_url}{path}"
    async with httpx.AsyncClient() as client:
        if verbose:
            click.echo(f"-> POST {url}", err=True)
        try:
            resp = await client.post(url, json=payload, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            click.echo(f"Error: {url} returned HTTP {e.response.status_code}", err=True)
            click.echo(e.response.text, err=True)
            raise SystemExit(1) from e
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            click.echo(f"Error: Cannot connect to service at {base_url}", err=True)
            click.echo("  Is the stack running?  docker-compose up -d", err=True)
            raise SystemExit(1) from e


@click.command(name="health")
@click.option("--via", type=click.Choice(["ace", "rhg", "both"]), default="both",
              help="Which service(s) to probe")
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE", help="Deployment profile (overrides the group default)")
@click.option("--ace-url", default=None, help="ACE service URL (overrides the profile)")
@click.option("--rhg-url", default=None, help="RHG service URL (overrides the profile)")
@click.option("--timeout", type=float, default=None, help="Request timeout in seconds (default 5)")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (overrides the group default)")
@click.pass_context
def health(ctx, via, profile, ace_url, rhg_url, timeout, output):
    """Check that the ACE and/or RHG services are reachable."""
    output = _output(ctx, output)
    timeout = _timeout(ctx, timeout, default=5.0)

    targets = []
    if via in ("ace", "both"):
        targets.append(("ace", _resolve_ace(ctx, profile, ace_url), "/health"))
    if via in ("rhg", "both"):
        targets.append(("rhg", _resolve_rhg(ctx, profile, rhg_url), "/health"))

    results = asyncio.run(_probe(targets, timeout, ctx.obj.verbose))

    if output == "json":
        click.echo(json.dumps(results, indent=2))
    elif ctx.obj.quiet:
        for r in results:
            detail = r.get("detail") or (r["body"].get("status") if isinstance(r.get("body"), dict) else "")
            click.echo(f"{r['service']}={'ok' if r['ok'] else 'down'} {detail}")
    else:
        for r in results:
            mark = click.style("OK", fg="green") if r["ok"] else click.style("DOWN", fg="red")
            body = r.get("body")
            detail = r.get("detail") or (body.get("status") if isinstance(body, dict) else "")
            click.echo(f"  {mark}  {r['service']:<4}  {r['url']}  {detail or ''}")

    if not all(r["ok"] for r in results):
        raise SystemExit(1)


async def _probe(targets, timeout, verbose):
    results = []
    async with httpx.AsyncClient() as client:
        for name, base, path in targets:
            url = f"{base}{path}"
            if verbose:
                click.echo(f"-> GET {url}", err=True)
            entry = {"service": name, "url": url, "ok": False, "status_code": None, "detail": ""}
            try:
                resp = await client.get(url, timeout=timeout)
                entry["status_code"] = resp.status_code
                try:
                    entry["body"] = resp.json()
                except ValueError:
                    entry["body"] = resp.text
                entry["ok"] = resp.status_code == 200
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                entry["detail"] = type(e).__name__
            results.append(entry)
    return results


@click.command(name="config")
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE", help="Deployment profile (overrides the group default)")
@click.option("--ace-url", default=None, help="ACE service URL (overrides the profile)")
@click.option("--rhg-url", default=None, help="RHG service URL (overrides the profile)")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (overrides the group default)")
@click.pass_context
def config(ctx, profile, ace_url, rhg_url, output):
    """Show the resolved profile, service endpoints, and relevant environment."""
    output = _output(ctx, output)
    try:
        resolved_profile = resolve_profile(pick(profile, ctx.obj.profile))
    except EndpointError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(2)

    def _try(resolver, override):
        try:
            return resolver(resolved_profile, override)
        except EndpointError as e:
            return f"<error: {e}>"

    data = {
        "profile": resolved_profile,
        "ace_url": _try(resolve_ace_url, pick(ace_url, ctx.obj.ace_url)),
        "rhg_url": _try(resolve_rhg_url, pick(rhg_url, ctx.obj.rhg_url)),
        "timeout": pick(ctx.obj.timeout),
        "output": output,
        "environment": {
            k: os.environ.get(k, "")
            for k in ("ACE_PROFILE", "ACE_URL", "RHG_URL", "MODEL_PROVIDER",
                      "AGENT_MAX_RETRIES", "AGENT_CONFIDENCE_THRESHOLD", "BLOCK_ON_SEVERITY")
        },
    }

    if output == "json":
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(f"  profile : {data['profile']}")
        click.echo(f"  ace_url : {data['ace_url']}")
        click.echo(f"  rhg_url : {data['rhg_url']}")
        click.echo("  environment:")
        for k, v in data["environment"].items():
            click.echo(f"    {k}={v}")


@click.command(name="mutate")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--type", "artifact_type", type=click.Choice(ARTIFACT_TYPES), default=None,
              help="Artifact type (defaults to inference from the filename)")
@click.option("--finding-id", "finding_ids", multiple=True,
              help="Finding id to associate with the patches (repeatable)")
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE", help="Deployment profile (overrides the group default)")
@click.option("--ace-url", default=None, help="ACE service URL (overrides the profile)")
@click.option("--timeout", type=float, default=None, help="Request timeout in seconds")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (overrides the group default)")
@click.pass_context
def mutate(ctx, path, artifact_type, finding_ids, profile, ace_url, timeout, output):
    """Generate RFC 6902 patches for a single artifact via ACE."""
    output = _output(ctx, output)
    timeout = _timeout(ctx, timeout)
    ace_url = _resolve_ace(ctx, profile, ace_url)

    p = Path(path)
    artifact = _load_yaml(p)
    if not isinstance(artifact, dict):
        click.echo(f"Error: could not parse {p.name} as a structured YAML/JSON object", err=True)
        raise SystemExit(1)

    payload = {
        "artifact_type": artifact_type or infer_type(p.name),
        "artifact": artifact,
        "finding_ids": list(finding_ids),
    }
    result = asyncio.run(_post_json(ace_url, "/ace/mutate", payload, timeout, ctx.obj.verbose))

    if output == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        patches = result.get("patches", [])
        if ctx.obj.quiet:
            click.echo(f"PATCHES={len(patches)}")
        else:
            click.echo(f"  Patches: {len(patches)}")
            for patch in patches:
                click.echo(f"    {patch.get('op')} {patch.get('path')}")


@click.command(name="scan-and-mutate")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--env", default="production", help="Target environment")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (overrides the group default)")
@click.option("--fail-on", type=click.Choice(SEVERITY_CHOICES), default="HIGH")
@click.option("--api-fail-on", type=click.Choice(SEVERITY_CHOICES), default=None)
@click.option("--api-min-severity", type=click.Choice(SEVERITY_CHOICES), default=None)
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE", help="Deployment profile (overrides the group default)")
@click.option("--ace-url", default=None, help="ACE service URL (overrides the profile)")
@click.option("--timeout", type=float, default=None, help="Request timeout in seconds")
@click.pass_context
def scan_and_mutate(ctx, paths, env, output, fail_on, api_fail_on, api_min_severity, profile, ace_url, timeout):
    """Scan artifacts and generate patches without applying them."""
    output = _output(ctx, output)
    timeout = _timeout(ctx, timeout)
    ace_url = _resolve_ace(ctx, profile, ace_url)
    g = ctx.obj or {}
    api_fail_on = api_fail_on or api_min_severity
    if not paths:
        paths = (".",)

    artifacts = collect_artifacts(paths)
    if not artifacts:
        click.echo("No supported artifacts found.", err=True)
        raise SystemExit(1)

    payload = {
        "pipeline_id": "cli-scan-and-mutate",
        "environment": env,
        "artifacts": artifacts,
        **({"api_min_severity": api_fail_on} if api_fail_on else {}),
    }
    result = asyncio.run(
        _post_json(ace_url, "/ace/scan-and-mutate", payload, timeout, ctx.obj.verbose)
    )

    if output == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        findings = result.get("findings", [])
        patches = result.get("patches", [])
        if ctx.obj.quiet:
            click.echo(
                f"{result.get('overall_severity', '?')} "
                f"risk={result.get('risk_score', '?')}/10 "
                f"findings={len(findings)} patches={len(patches)}"
            )
        else:
            click.echo("")
            click.echo("=" * 60)
            click.echo(f"  Risk Score: {result.get('risk_score', '?')}/10")
            click.echo(f"  Severity:   {result.get('overall_severity', '?')}")
            click.echo(f"  Findings:   {len(findings)}   Patches: {len(patches)}")
            click.echo("=" * 60)
            for patch in patches:
                click.echo(f"  {patch.get('op')} {patch.get('path')}")
            click.echo("")

    if _passes_gate(result.get("overall_severity", "INFO"), fail_on):
        raise SystemExit(1)


@click.command(name="submit")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--env", default="production", help="Target environment")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (overrides the group default)")
@click.option("--fail-on", type=click.Choice(SEVERITY_CHOICES), default="HIGH",
              help="Exit non-zero when blocking severity is at least this level")
@click.option("--api-fail-on", type=click.Choice(SEVERITY_CHOICES), default=None)
@click.option("--api-min-severity", type=click.Choice(SEVERITY_CHOICES), default=None)
@click.option("--repo", default="unknown/repo", show_default=True, help="Repository slug")
@click.option("--branch", default="main", show_default=True, help="Branch name")
@click.option("--backend-path", multiple=True, type=click.Path(exists=True),
              help="Backend source file or directory to analyze (repeatable; .env is never sent)")
@click.option("--all", "scan_all", is_flag=True, help="Scan all supported artifacts in current directory")
@click.option("--infra", is_flag=True, help="Scan common infra dirs (k8s, infra, manifests, terraform)")
@click.option("--backend", "scan_backend", is_flag=True, help="Auto-scan common backend dirs (services, src, app, backend)")
@click.option("--write-dir", type=click.Path(file_okay=False), default=None,
              help="Write patched artifacts into this directory")
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE", help="Deployment profile (overrides the group default)")
@click.option("--rhg-url", default=None, help="RHG service URL (overrides the profile)")
@click.option("--timeout", type=float, default=None, help="Request timeout in seconds (default 60)")
@click.pass_context
def submit(ctx, paths, env, output, fail_on, api_fail_on, api_min_severity, repo, branch, backend_path, scan_all, infra, scan_backend, write_dir,
           profile, rhg_url, timeout):
    """Submit artifacts to the RHG gate for a deploy/no-deploy decision."""
    output = _output(ctx, output)
    timeout = _timeout(ctx, timeout, default=60.0)
    rhg_url = _resolve_rhg(ctx, profile, rhg_url)
    
    backend_paths = list(backend_path)
    scan_paths = list(paths)
    
    if scan_all and not scan_paths:
        scan_paths = ["."]
    if infra and not scan_paths:
        for d in ["k8s", "infra", "manifests", "terraform", "helm", "charts"]:
            if Path(d).exists():
                scan_paths.append(d)
        if not scan_paths:
            for pattern in ("*.yml", "*.yaml", "Dockerfile*", "docker-compose*"):
                for p in sorted(Path('.'.glob(pattern))):
                    if p.is_file() and str(p) not in scan_paths:
                        scan_paths.append(str(p))
        if not scan_paths:
            click.echo("No common infra directories found (k8s, infra, manifests, terraform, helm, charts).", err=True)
            raise SystemExit(1)
        if not scan_paths:
            scan_paths = ["."]
    if scan_backend:
        for d in ["services", "src", "app", "backend", "api", "server"]:
            if Path(d).exists() and d not in backend_paths:
                backend_paths.append(d)
        if not scan_paths or scan_paths == (".",):
            for d in ["services", "src", "app", "backend", "api", "server"]:
                if Path(d).exists() and d not in scan_paths:
                    scan_paths.append(d)
    
    if not scan_paths:
        scan_paths = (".",)

    artifacts = collect_artifacts(scan_paths)
    if not artifacts:
        click.echo("No supported artifacts found.", err=True)
        raise SystemExit(1)

    payload = {
        "pipeline_id": "cli-submit",
        "repo": repo,
        "branch": branch,
        "environment": env,
        "artifacts": artifacts,
        "backend_source": collect_backend(backend_paths),
    }
    if hasattr(ctx.obj, 'verbose'):
        verbose = ctx.obj.verbose
    else:
        verbose = False
    result = asyncio.run(_post_json(rhg_url, "/rhg/submit", payload, timeout, verbose))
    decision = result.get("decision", "?")

    if output == "json":
        click.echo(json.dumps(result, indent=2))
    elif ctx.obj.quiet:
        click.echo(
            f"DECISION={decision} mutations={result.get('mutations_applied', 0)} "
            f"blocking={len(result.get('blocking_findings', []))}"
        )
    else:
        color = {"ALLOW": "green", "PATCHED": "yellow", "BLOCK": "red"}.get(decision, "white")
        click.echo("")
        click.echo("=" * 60)
        click.echo(f"  Decision:      {click.style(decision, fg=color, bold=True)}")
        click.echo(f"  Scan ID:       {result.get('scan_id', '?')}")
        click.echo(
            f"  Mutations:     {result.get('mutations_applied', 0)} applied "
            f"({result.get('mutator_retries', 0)} retries)"
        )
        click.echo(f"  Compatibility: {result.get('compatibility_verdict', '?')}")
        click.echo(f"  Ops notified:  {'Yes' if result.get('ops_notified') else 'No'}")
        click.echo("=" * 60)
        blocking = result.get("blocking_findings", [])
        if blocking:
            click.echo("  Blocking findings:")
            for f in blocking:
                sev = f.get("severity", "?")
                rule_id = f.get("rule_id", "?")
                msg = f.get("message") or f.get("title") or f.get("description") or ""
                artifact = f.get("artifact") or f.get("file") or ""
                line = f.get("line_number") or f.get("line")
                snippet = f.get("snippet") or f.get("code_snippet")
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "white"}.get(sev, "white")
                click.echo(f"    [{click.style(sev, fg=color)}] {rule_id}  {artifact}{':' + str(line) if line else ''}")
                if msg:
                    click.echo(f"         {msg}")
                if snippet:
                    click.echo(f"         {snippet}")
        click.echo("")

    patched = result.get("patched_artifacts") or []
    if write_dir and patched:
        out = Path(write_dir)
        out.mkdir(parents=True, exist_ok=True)
        for art in patched:
            target = out / art.get("name", "artifact")
            target.write_bytes(base64.b64decode(art.get("content", "")))
            if output != "json":
                click.echo(f"  wrote {target}")

    if decision == "BLOCK" or _passes_gate(_max_severity(result.get("blocking_findings", [])), fail_on):
        raise SystemExit(1)
