import asyncio
import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

import click
import httpx

from ace_compliance.config import EndpointError, resolve_ace_url
from ace_compliance.helpers import (
    PROFILE_CHOICES,
    SEVERITY_CHOICES,
    SEVERITY_ORDER,
    GlobalOptions,
    collect_artifacts,
    collect_backend,
    collect_source_artifacts,
    discover_infra_paths,
    pick,
    resolve_backend_roots,
)


def _package_version() -> str:
    try:
        return _pkg_version("ace-compliance")
    except PackageNotFoundError:
        return "0.0.0+unknown"


@click.group()
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE",
              help="Deployment profile: local, cloud, or auto. Default for all commands.")
@click.option("--ace-url", default=None, help="ACE service URL (default for all commands).")
@click.option("--rhg-url", default=None, help="RHG service URL (default for all commands).")
@click.option("--timeout", type=float, default=None,
              help="Request timeout in seconds (default for all commands).")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (default for all commands).")
@click.option("-q", "--quiet", is_flag=True, default=False,
              help="Reduce output to essentials.")
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Print resolved endpoints and request details to stderr.")
@click.version_option(version=_package_version(), prog_name="ace")
@click.pass_context
def cli(ctx, profile, ace_url, rhg_url, timeout, output, quiet, verbose):
    """ace-compliance — scan infrastructure before it ships."""
    ctx.obj = GlobalOptions(profile, ace_url, rhg_url, timeout, output, quiet, verbose)


@cli.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--env", default="production", help="Target environment")
@click.option("--output", type=click.Choice(["text", "json"]), default=None,
              help="Output format (overrides the group default)")
@click.option("--fail-on", type=click.Choice(SEVERITY_CHOICES), default="HIGH")
@click.option("--api-fail-on", type=click.Choice(SEVERITY_CHOICES), default=None)
@click.option("--api-min-severity", type=click.Choice(SEVERITY_CHOICES), default=None)
@click.option("--backend-path", multiple=True, type=click.Path(exists=True),
              help="Backend source file or directory to analyze (repeatable)")
@click.option("--all", "scan_all", is_flag=True, help="Scan all supported artifacts in current directory")
@click.option("--infra", is_flag=True, help="Scan common infra dirs (k8s, infra, manifests, terraform)")
@click.option("--backend", "scan_backend", is_flag=True, help="Auto-scan common backend dirs (services, src, app, backend)")
@click.option("--profile", type=click.Choice(PROFILE_CHOICES), default=None,
              envvar="ACE_PROFILE", help="Deployment profile (overrides the group default)")
@click.option("--ace-url", default=None, help="ACE service URL (overrides the profile)")
@click.option("--timeout", type=float, default=None, help="Request timeout in seconds")
@click.pass_context
def scan(ctx, paths, env, output, fail_on, api_fail_on, api_min_severity, backend_path, scan_all, infra, scan_backend, profile, ace_url, timeout):
    """Scan one or more artifact files for compliance violations."""
    g = ctx.obj
    output = pick(output, g.output, default="text")
    timeout = pick(timeout, g.timeout, default=30.0)
    try:
        ace_url = resolve_ace_url(pick(profile, g.profile), pick(ace_url, g.ace_url))
    except EndpointError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(2)
    
    backend_paths = list(backend_path)
    scan_paths = list(paths)

    if scan_all and not scan_paths:
        scan_paths = ["."]
    if infra and not scan_paths:
        scan_paths = discover_infra_paths()
        if not scan_paths:
            click.echo(
                "No infra artifacts found (k8s, infra, manifests, terraform, helm, "
                "charts, or root Dockerfile/compose/YAML files).",
                err=True,
            )
            raise SystemExit(1)

    backend_only = scan_backend and not infra and not scan_all
    if scan_backend:
        for p in resolve_backend_roots(list(backend_path), list(paths)):
            if p not in backend_paths:
                backend_paths.append(p)
        if backend_only:
            scan_paths = []

    if not scan_paths:
        scan_paths = [] if backend_only else (".",)

    if api_min_severity:
        api_fail_on = api_min_severity
    asyncio.run(
        _scan(
            scan_paths,
            env,
            output,
            fail_on,
            ace_url,
            timeout,
            g.verbose,
            g.quiet,
            backend_paths,
            api_fail_on,
        )
    )


async def _scan(paths, env, output, fail_on, ace_url, timeout, verbose, quiet, backend_paths=None, api_fail_on=None):
    artifacts = collect_artifacts(paths)
    if backend_paths:
        artifacts.extend(collect_source_artifacts(backend_paths))
    if not artifacts:
        click.echo("No supported artifacts found.", err=True)
        raise SystemExit(1)

    async with httpx.AsyncClient() as client:
        if verbose:
            click.echo(f"-> POST {ace_url}/ace/scan", err=True)
        try:
            resp = await client.post(
                f"{ace_url}/ace/scan",
                json={
                    "pipeline_id": "cli-scan",
                    "environment": env,
                    "artifacts": artifacts,
                    "backend_source": collect_backend(backend_paths or []),
                    **({"api_min_severity": api_fail_on} if api_fail_on else {}),
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            click.echo(f"Error: Cannot connect to ACE service at {ace_url}", err=True)
            click.echo("", err=True)
            click.echo("  Make sure the ACE service is running:", err=True)
            click.echo("    docker-compose up -d          # start full stack", err=True)
            click.echo(f"    curl {ace_url}/health         # verify it's up", err=True)
            click.echo("", err=True)
            raise SystemExit(1) from e

    if output == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        _print_text_report(result, quiet=quiet)

    overall = result.get("overall_severity", "INFO")
    if SEVERITY_ORDER.get(overall, 0) >= SEVERITY_ORDER.get(fail_on, 0):
        raise SystemExit(1)


def _print_text_report(result: dict, quiet: bool = False):
    findings = result.get("findings", [])
    if quiet:
        click.echo(
            f"{result.get('overall_severity', '?')} "
            f"risk={result.get('risk_score', '?')}/10 findings={len(findings)}"
        )
        return
    click.echo("")
    click.echo("=" * 60)
    click.echo(f"  Risk Score:  {result.get('risk_score', '?')}/10")
    click.echo(f"  Severity:    {result.get('overall_severity', '?')}")
    click.echo(f"  Findings:    {len(findings)}")
    click.echo("=" * 60)
    for f in findings:
        sev = f.get("severity", "?")
        rule_id = f.get("rule_id", "?")
        msg = f.get("message") or f.get("title") or f.get("description") or ""
        artifact = f.get("artifact") or f.get("file") or ""
        line = f.get("line_number") or f.get("line")
        snippet = f.get("snippet") or f.get("code_snippet")
        color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "white"}.get(sev, "white")
        click.echo(f"  [{click.style(sev, fg=color)}] {rule_id}  {artifact}{':' + str(line) if line else ''}")
        if msg:
            click.echo(f"       {msg}")
        if snippet:
            click.echo(f"       {snippet}")
    click.echo("")


from ace_compliance.agent_cli import agent  # noqa: E402
from ace_compliance.auth_cli import auth  # noqa: E402
from ace_compliance.history_cli import history  # noqa: E402
from ace_compliance.service_cli import (  # noqa: E402
    config,
    health,
    mutate,
    scan_and_mutate,
    submit,
)

cli.add_command(agent)
cli.add_command(health)
cli.add_command(config)
cli.add_command(mutate)
cli.add_command(scan_and_mutate)
from ace_compliance.admin_cli import admin  # noqa: E402
from ace_compliance.agent_cli import agent  # noqa: E402
from ace_compliance.service_cli import (  # noqa: E402
    config,
    health,
    mutate,
    scan_and_mutate,
)

cli.add_command(agent)
cli.add_command(health)
cli.add_command(config)
cli.add_command(mutate)
cli.add_command(scan_and_mutate)
cli.add_command(submit)
cli.add_command(history)
cli.add_command(auth)
cli.add_command(admin)


if __name__ == "__main__":
    cli()


@cli.command(name="init")
@click.pass_context
def init_cmd(ctx):
    """Quick setup guide for new orgs and repos."""
    click.echo("ACE Setup Guide")
    click.echo("================")
    click.echo("")
    click.echo("1) Admin: Create org/project and generate API key")
    click.echo("   ace create-org <org> [--name ...]")
    click.echo("   ace add-repo <org> <project> [--repo owner/repo]")
    click.echo("   ace gen-key <org> <project> [--scopes scan,submit]")
    click.echo("")
    click.echo("2) Use API key")
    click.echo("   ace login --api-key ace_sk_... [--org <org>]")
    click.echo("   ace whoami")
    click.echo("")
    click.echo("3) Run gate")
    click.echo("   ace scan ./k8s --profile local")
    click.echo("   ace submit ./k8s --repo owner/repo --branch main --env prod --fail-on HIGH")
    click.echo("")
    click.echo("4) View history")
    click.echo("   ace history --limit 10")
from ace_compliance.admin_cli import (  # noqa: E402
    add_repo_alias,
    create_org_alias,
    gen_key_alias,
)
from ace_compliance.auth_cli import (  # noqa: E402
    login_alias,
    logout_alias,
    whoami_alias,
)

cli.add_command(login_alias)
cli.add_command(whoami_alias)
cli.add_command(logout_alias)
cli.add_command(create_org_alias)
cli.add_command(add_repo_alias)
cli.add_command(gen_key_alias)
cli.add_command(init_cmd)
