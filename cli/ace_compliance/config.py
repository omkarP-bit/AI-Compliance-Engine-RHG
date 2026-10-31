"""Deployment-aware endpoint resolution for the CLI.

The CLI can talk to a locally-run stack (docker-compose) or a deployed backend.
Which one it uses is an explicit choice, not an accident of a globally exported
``ACE_URL`` (the README suggests adding one to your shell profile, which then
silently shadows local runs):

* ``ACE_PROFILE=local``  always localhost, ignoring a stray ``ACE_URL``
* ``ACE_PROFILE=cloud``  use ``ACE_URL`` (required); ``RHG_URL`` falls back to it
* ``ACE_PROFILE=auto``   use ``ACE_URL`` / ``RHG_URL`` when set, else local

An explicit ``--ace-url`` / ``--rhg-url`` always wins over the profile.
"""

from __future__ import annotations

import os

ACE_LOCAL_URL = "http://localhost:8000"
RHG_LOCAL_URL = "http://localhost:8001"

PROFILES = ("local", "cloud", "auto")


class EndpointError(ValueError):
    """Raised when the selected profile is missing a required URL."""


def resolve_profile(profile: str | None = None) -> str:
    chosen = (profile or os.environ.get("ACE_PROFILE") or "auto").strip().lower()
    if chosen not in PROFILES:
        raise EndpointError(
            f"Unknown profile {chosen!r}; expected one of {', '.join(PROFILES)}"
        )
    return chosen


def resolve_ace_url(profile: str | None = None, override: str | None = None) -> str:
    chosen = resolve_profile(profile)
    if override:
        return override
    if chosen == "local":
        return ACE_LOCAL_URL
    if chosen == "cloud":
        url = os.environ.get("ACE_URL")
        if not url:
            raise EndpointError("ACE_PROFILE=cloud requires ACE_URL to be set")
        return url
    return os.environ.get("ACE_URL") or ACE_LOCAL_URL


def resolve_rhg_url(profile: str | None = None, override: str | None = None) -> str:
    chosen = resolve_profile(profile)
    if override:
        return override
    if chosen == "local":
        return RHG_LOCAL_URL
    if chosen == "cloud":
        url = os.environ.get("RHG_URL") or os.environ.get("ACE_URL")
        if not url:
            raise EndpointError("ACE_PROFILE=cloud requires ACE_URL or RHG_URL to be set")
        return url
    return os.environ.get("RHG_URL") or os.environ.get("ACE_URL") or RHG_LOCAL_URL
