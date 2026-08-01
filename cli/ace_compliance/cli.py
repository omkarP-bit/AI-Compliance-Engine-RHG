import asyncio
import base64
import json
import os
from pathlib import Path

import click
import httpx

ACE_URL = os.environ.get("ACE_URL")
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@click.group()
def cli():
    """ace-compliance — scan infrastructure before it ships."""


@cli.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--env", default="production", help="Target environment")
@click.option("--output", type=click.Choice(["text", "json"]), default="text")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default="HIGH")
@click.option("--ace-url", envvar="ACE_URL", default=None, help="ACE service URL (required, or set ACE_URL env var)")
def scan(paths, env, output, fail_on, ace_url):
    """Scan one or more artifact files for compliance violations."""
    if not paths:
        paths = ("." ,)
    asyncio.run(_scan(list(paths), env, output, fail_on, ace_url))


async def _scan(paths: list[str], env: str, output: str, fail_on: str, ace_url: str):
    if not ace_url:
        raise click.UsageError(
            "ACE service URL required. Set --ace-url or ACE_URL env var.\n"
            "  export ACE_URL=https://fw6mh9jzpc.execute-api.ap-south-1.amazonaws.com\n"
            "  ace scan --ace-url $ACE_URL ."
        )
    artifacts = []

    for path_str in paths:
        p = Path(path_str)
        if p.is_dir():
            for f in p.rglob("*.yaml"):
                artifacts.append(_make_artifact(f))
            for f in p.rglob("*.yml"):
                artifacts.append(_make_artifact(f))
            for f in p.rglob("*.tf"):
                artifacts.append(_make_artifact(f))
            for f in p.rglob("Dockerfile*"):
                artifacts.append(_make_artifact(f))
        else:
            artifacts.append(_make_artifact(p))

    if not artifacts:
        click.echo("No supported artifacts found.", err=True)
        raise SystemExit(1)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{ace_url}/ace/scan",
                json={
                    "pipeline_id": "cli-scan",
                    "environment": env,
                    "artifacts": artifacts,
                },
                timeout=30.0,
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
        _print_text_report(result)

    overall = result.get("overall_severity", "INFO")
    if SEVERITY_ORDER.get(overall, 0) >= SEVERITY_ORDER.get(fail_on, 0):
        raise SystemExit(1)


def _make_artifact(path: Path) -> dict:
    name = path.name
    ext = path.suffix
    if name == "Dockerfile" or name.endswith(".dockerfile"):
        artifact_type = "dockerfile"
    elif name in (
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ) or (name.startswith("docker-compose.") and name.endswith((".yml", ".yaml"))):
        artifact_type = "docker_compose"
    elif ext in (".yaml", ".yml"):
        artifact_type = "kubernetes"
    elif ext in (".tf", ".tf.json"):
        artifact_type = "terraform"
    else:
        artifact_type = "kubernetes"
    return {
        "type": artifact_type,
        "name": name,
        "content": base64.b64encode(path.read_bytes()).decode(),
    }


def _print_text_report(result: dict):
    findings = result.get("findings", [])
    click.echo("")
    click.echo("=" * 60)
    click.echo(f"  Risk Score:  {result.get('risk_score', '?')}/10")
    click.echo(f"  Severity:    {result.get('overall_severity', '?')}")
    click.echo(f"  Findings:    {len(findings)}")
    click.echo("=" * 60)
    for f in findings:
        sev = f.get("severity", "?")
        rule_id = f.get("rule_id", "?")
        msg = f.get("message", "")
        artifact = f.get("artifact", "")
        color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "white"}.get(sev, "white")
        click.echo(f"  [{click.style(sev, fg=color)}] {rule_id}  {artifact}")
        click.echo(f"       {msg}")
    click.echo("")


if __name__ == "__main__":
    cli()
