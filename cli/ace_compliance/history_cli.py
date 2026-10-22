"""Read-only history command: merges git log with activity store (if available)."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime

import click


def _get_git_log(limit: int) -> list[dict]:
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                f"-n{limit}",
                "--format=%H%x00%an%x00%ae%x00%at%x00%s",
            ],
            cwd=".",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []

    if result.returncode != 0:
        return []

    entries = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\x00")
        if len(parts) != 5:
            continue
        sha, author, email, ts, msg = parts
        try:
            dt = datetime.fromtimestamp(int(ts)).isoformat()
        except Exception:
            dt = ts
        entries.append(
            {
                "source": "git",
                "sha": sha[:8],
                "author": author,
                "email": email,
                "time": dt,
                "message": msg,
            }
        )
    return entries


def _get_activity(limit: int) -> list[dict]:
    try:
        from common.storage import get_storage_backend

        backend = get_storage_backend()
        items = backend.list_recent_activity(limit=limit)
        for item in items:
            item["source"] = "activity"
        return items
    except Exception:
        return []


@click.command(name="history")
@click.option("--source", type=click.Choice(["git", "activity", "all"]), default="all")
@click.option("--limit", type=int, default=20)
@click.option("--output", type=click.Choice(["text", "json"]), default=None)
@click.pass_context
def history(ctx, source, limit, output):
    """Show recent git history and/or ACE activity."""
    g = ctx.obj
    out = output or getattr(g, "output", None) or "text"

    git_entries = _get_git_log(limit) if source in ("git", "all") else []
    activity_entries = _get_activity(limit) if source in ("activity", "all") else []

    merged = []
    for e in git_entries:
        merged.append(e)
    for e in activity_entries:
        merged.append(e)

    merged.sort(key=lambda x: x.get("time") or x.get("created_at") or "", reverse=True)
    merged = merged[:limit]

    if out == "json":
        click.echo(json.dumps(merged, indent=2))
        return

    if not merged:
        click.echo("No history found.")
        return

    for entry in merged:
        if entry.get("source") == "git":
            click.echo(f"[git] {entry.get('time')} {entry.get('sha')} {entry.get('author')}: {entry.get('message')}")
        else:
            click.echo(
                f"[activity] {entry.get('time') or entry.get('created_at')} "
                f"{entry.get('event_type')} repo={entry.get('repo')} "
                f"decision={entry.get('gate_decision')} "
                f"findings={entry.get('findings_count')} "
                f"mutations={entry.get('mutations_applied')}"
            )
