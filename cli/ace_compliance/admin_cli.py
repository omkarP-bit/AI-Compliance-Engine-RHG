"""Admin CLI for orgs/projects/API keys (local/dev)."""

from __future__ import annotations

from datetime import datetime

import click
from common.auth import generate_api_key, hash_api_key
from common.storage import ApiKeyRecord, OrgRecord, ProjectRecord, get_storage_backend


@click.group(name="admin")
def admin():
    """Admin commands to manage orgs, projects and API keys."""
    pass


@admin.command(name="org-create")
@click.argument("org_id")
@click.option("--name", default=None)
def org_create(org_id, name):
    store = get_storage_backend()
    store.create_org(OrgRecord(org_id=org_id, name=name or org_id, created_at=datetime.utcnow()))
    click.echo(f"Created org: {org_id}")


@admin.command(name="project-create")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo", default=None)
def project_create(org_id, project_id, repo):
    store = get_storage_backend()
    store.create_project(ProjectRecord(org_id=org_id, project_id=project_id, repo=repo, created_at=datetime.utcnow()))
    click.echo(f"Created project: {org_id}/{project_id}")


@admin.command(name="key-create")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo-pattern", default=None)
@click.option("--scopes", default="scan,submit")
def key_create(org_id, project_id, repo_pattern, scopes):
    store = get_storage_backend()
    key = generate_api_key()
    key_id = key.split("_")[-1][:12]
    store.create_api_key(
        ApiKeyRecord(
            key_id=key_id,
            key_hash=hash_api_key(key),
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
    store = get_storage_backend()
    keys = store.list_api_keys(org_id)
    for k in keys:
        click.echo(f"{k['key_id']} org={k['org_id']} project={k.get('project_id')} scopes={k.get('scopes')} revoked={bool(k.get('revoked_at'))}")


@admin.command(name="key-revoke")
@click.argument("key_id")
def key_revoke(key_id):
    store = get_storage_backend()
    store.revoke_api_key(key_id)
    click.echo(f"Revoked key: {key_id}")


# Friendly aliases
@click.command(name="create-org")
@click.argument("org_id")
@click.option("--name", default=None)
def create_org_alias(org_id, name):
    store = get_storage_backend()
    from datetime import datetime

    from common.storage import OrgRecord
    store.create_org(OrgRecord(org_id=org_id, name=name or org_id, created_at=datetime.utcnow()))
    click.echo(f"Created org: {org_id}")


@click.command(name="add-repo")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo", default=None)
def add_repo_alias(org_id, project_id, repo):
    store = get_storage_backend()
    from datetime import datetime

    from common.storage import ProjectRecord
    store.create_project(ProjectRecord(org_id=org_id, project_id=project_id, repo=repo, created_at=datetime.utcnow()))
    click.echo(f"Added repo: {org_id}/{project_id}" + (f" ({repo})" if repo else ""))


@click.command(name="gen-key")
@click.argument("org_id")
@click.argument("project_id")
@click.option("--repo-pattern", default=None)
@click.option("--scopes", default="scan,submit")
def gen_key_alias(org_id, project_id, repo_pattern, scopes):
    store = get_storage_backend()
    from datetime import datetime

    from common.auth import generate_api_key, hash_api_key
    from common.storage import ApiKeyRecord
    key = generate_api_key()
    key_id = key.split("_")[-1][:12]
    store.create_api_key(
        ApiKeyRecord(
            key_id=key_id,
            key_hash=hash_api_key(key),
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
