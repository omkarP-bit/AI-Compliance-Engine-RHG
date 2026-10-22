"""CLI auth stubs (API key based)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click


def _cred_path() -> Path:
    base = Path.home() / ".config" / "ace"
    base.mkdir(parents=True, exist_ok=True)
    return base / "credentials.json"


@click.group(name="auth")
def auth():
    """Manage ACE CLI credentials."""
    pass


@auth.command(name="login")
@click.option("--api-key", prompt=True, hide_input=True)
@click.option("--org", default=None)
def login(api_key, org):
    """Save an API key to local credentials file."""
    path = _cred_path()
    data = {"api_key": api_key}
    if org:
        data["org"] = org
    path.write_text(json.dumps(data, indent=2))
    os.chmod(path, 0o600)
    click.echo(f"Saved credentials to {path}")


@auth.command(name="whoami")
def whoami():
    """Show current credentials context."""
    if os.environ.get("ACE_API_KEY"):
        click.echo("ACE_API_KEY is set in environment")
        return
    path = _cred_path()
    if not path.exists():
        click.echo("Not logged in. Run 'ace auth login' or set ACE_API_KEY.")
        return
    try:
        data = json.loads(path.read_text())
        click.echo(f"api_key: {data.get('api_key','')[:12]}...")
        if data.get("org"):
            click.echo(f"org: {data['org']}")
    except Exception as e:
        click.echo(f"Error reading credentials: {e}", err=True)


@auth.command(name="logout")
def logout():
    """Remove saved credentials."""
    path = _cred_path()
    if path.exists():
        path.unlink()
        click.echo("Logged out.")
    else:
        click.echo("No saved credentials.")
