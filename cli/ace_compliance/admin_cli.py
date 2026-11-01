"""Admin CLI for orgs/projects/API keys (local/dev).

These commands operate on the server-side storage backend, which lives in the
``common`` package shipped with the ACE services (not in the published CLI
wheel). The import is therefore lazy: ``ace scan``/``ace config`` must work
from a plain ``pip install ace-compliance``, and only ``ace admin`` asks for
the server package.
"""

from __future__ import annotations

from datetime import datetime

import click


def _server_modules():
    """Import ``common.auth``/``common.storage`` or fail with a clear message."""
    try:
        from common import auth, storage
    except ImportError as exc:  # pragma: no cover - depends on install layout
        raise click.ClickException(
            "Admin commands need the ACE server package ('common'), which is "
            "not part of the CLI wheel.\n"
            "Run them from the ACE+RHG repository with services/ on PYTHONPATH, e.g.\n"
            "  PYTHONPATH=services ace admin org-create acme"
        ) from exc
    return auth, storage


@click.group(name="admin")
def admin():
    """Admin commands to manage orgs, projects and API keys."""
    pass


@admin.command(name="org-create")
@click.argument("org_id")
@click.option("--name", default=None)
def org_create(org_id, name):
    _, storage = _server_modules()
    store = storage.get_storage_backend()
    store.create_org(
        storage.OrgRecord(
            org_id=org_id, name=name or org_id, created_at=datetime.utcnow()
        )
    )
    click.echo(f"Created org: {org_id}")


@admin.command(name="project-create")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo", default=None)
def project_create(org_id, project_id, repo):
    _, storage = _server_modules()
    store = storage.get_storage_backend()
    store.create_project(
        storage.ProjectRecord(
            org_id=org_id, project_id=project_id, repo=repo, created_at=datetime.utcnow()
        )
    )
    click.echo(f"Created project: {org_id}/{project_id}")


@admin.command(name="key-create")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo-pattern", default=None)
@click.option("--scopes", default="scan,submit")
def key_create(org_id, project_id, repo_pattern, scopes):
    auth, storage = _server_modules()
    store = storage.get_storage_backend()
    key = auth.generate_api_key()
    key_id = key.split("_")[-1][:12]
    store.create_api_key(
        storage.ApiKeyRecord(
            key_id=key_id,
            key_hash=auth.hash_api_key(key),
            org_id=org_id,
            project_id=project_id,
            repo_pattern=repo_pattern,
            scopes=scopes.split(","),
            created_at=datetime.utcnow(),
        )
    )
    click.echo("API KEY (save this - shown once):")
    click.echo(key)
    click.echo(f"key_id: {key_id}")


@admin.command(name="key-list")
@click.option("--org-id", default=None)
def key_list(org_id):
    _, storage = _server_modules()
    store = storage.get_storage_backend()
    keys = store.list_api_keys(org_id)
    for k in keys:
        click.echo(f"{k['key_id']} org={k['org_id']} project={k.get('project_id')} scopes={k.get('scopes')} revoked={bool(k.get('revoked_at'))}")


@admin.command(name="key-revoke")
@click.argument("key_id")
def key_revoke(key_id):
    _, storage = _server_modules()
    store = storage.get_storage_backend()
    store.revoke_api_key(key_id)
    click.echo(f"Revoked key: {key_id}")


# Friendly aliases
@click.command(name="create-org")
@click.argument("org_id")
@click.option("--name", default=None)
def create_org_alias(org_id, name):
    _, storage = _server_modules()
    store = storage.get_storage_backend()
    store.create_org(
        storage.OrgRecord(
            org_id=org_id, name=name or org_id, created_at=datetime.utcnow()
        )
    )
    click.echo(f"Created org: {org_id}")


@click.command(name="add-repo")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo", default=None)
def add_repo_alias(org_id, project_id, repo):
    _, storage = _server_modules()
    store = storage.get_storage_backend()
    store.create_project(
        storage.ProjectRecord(
            org_id=org_id, project_id=project_id, repo=repo, created_at=datetime.utcnow()
        )
    )
    click.echo(f"Added repo: {org_id}/{project_id}" + (f" ({repo})" if repo else ""))


@click.command(name="gen-key")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo-pattern", default=None)
@click.option("--scopes", default="scan,submit")
def gen_key_alias(org_id, project_id, repo_pattern, scopes):
    auth, storage = _server_modules()
    store = storage.get_storage_backend()
    key = auth.generate_api_key()
    key_id = key.split("_")[-1][:12]
    store.create_api_key(
        storage.ApiKeyRecord(
            key_id=key_id,
            key_hash=auth.hash_api_key(key),
            org_id=org_id,
            project_id=project_id,
            repo_pattern=repo_pattern,
            scopes=scopes.split(","),
            created_at=datetime.utcnow(),
        )
    )
    click.echo("API KEY (save this - shown once):")
    click.echo(key)
    click.echo(f"key_id: {key_id}")
