"""Artifact decoding/encoding and policy-path resolution for the release loop.

The agentic graph mutates artifacts, so it needs the exact same normalisation
that ``/ace/scan`` used to produce the findings. Re-deriving that logic here
would let the two paths drift, so this module is the single place the graph
reaches for it: it imports :data:`ace.api.routes.PARSERS` and
:data:`ace.api.routes.POLICY_MAP` rather than duplicating either.

Two invariants this module enforces:

* Findings carry JSON-Pointer paths into the *OPA-normalised* document (e.g.
  ``/spec/containers/0/securityContext/privileged``), so mutations must be
  applied to the normalised form, not the raw manifest. This mirrors the v2
  ``/rhg/submit`` pipeline exactly.
* Non-YAML artifact types (Terraform plan JSON, Dockerfile, GitHub Actions
  workflow) must round-trip through their own serialiser. The graph operates on
  all five artifact types, so a hardcoded ``yaml.safe_load``/``yaml.dump`` is
  not an option.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

import yaml

from ace.api.routes import PARSERS, POLICY_MAP

DEFAULT_POLICY_PATH = POLICY_MAP["kubernetes"]

#: Artifact types whose normalised document is serialised as YAML rather than JSON.
YAML_ARTIFACT_TYPES = frozenset({"kubernetes", "helm", "github_actions"})


class ArtifactDecodeError(ValueError):
    """Raised when an artifact body cannot be decoded into a policy input."""


def policy_path_for(artifact_type: str) -> str:
    """Resolve the OPA document path for a normalized artifact type."""
    return POLICY_MAP.get(artifact_type, DEFAULT_POLICY_PATH)


def decode_artifact(artifact: dict) -> dict:
    """Decode one ``{type, name, content}`` entry into its OPA-normalised form.

    The artifact is routed through the same parser chain as ``/ace/scan`` so
    that JSON-Pointer paths in the resulting findings resolve against the
    returned document. If no parser claims the file, the body is decoded
    structurally (YAML first, then JSON) as a best effort.
    """
    name = artifact.get("name", "")
    content = decode_content(artifact.get("content", ""))

    parser = next((p for p in PARSERS if p.supports(name)), None)
    if parser is not None:
        return parser.parse(content, name).raw

    return _decode_structural(content)


def encode_artifact(document: dict, artifact_type: str) -> str:
    """Serialise a normalised document back to a request/artifact body."""
    if artifact_type in YAML_ARTIFACT_TYPES:
        return yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
    return json.dumps(document, indent=2)


def decode_content(content: str) -> str:
    """Base64-decode an artifact body."""
    try:
        return base64.b64decode(content, validate=False).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as exc:
        raise ArtifactDecodeError(f"artifact body is not valid base64: {exc}") from exc


def encode_content(document: dict, artifact_type: str) -> str:
    """Serialise and base64-encode a normalised document."""
    return base64.b64encode(encode_artifact(document, artifact_type).encode()).decode()


def artifact_type_of(artifact: dict) -> str:
    """Best-effort artifact type for a request entry.

    Prefers the declared ``type`` but falls back to what the parser chain
    infers from the filename, so a caller that omits ``type`` still routes to
    the right serialiser.
    """
    declared = (artifact.get("type") or "").strip()
    if declared:
        return declared

    name = artifact.get("name", "")
    parser = next((p for p in PARSERS if p.supports(name)), None)
    if parser is None:
        return "kubernetes"

    try:
        return parser.parse("", name).artifact_type
    except Exception:  # noqa: BLE001 - type inference is best effort
        return "kubernetes"


def find_artifact(artifacts: list[dict], name: str) -> dict | None:
    """Locate a request artifact by name."""
    for artifact in artifacts or []:
        if artifact.get("name") == name:
            return artifact
    return None


def _decode_structural(content: str) -> dict[str, Any]:
    """Decode a body that no parser claimed, preferring YAML then JSON."""
    for loader in (yaml.safe_load_all, json.loads):
        try:
            docs = list(loader(content)) if loader is yaml.safe_load_all else [loader(content)]
        except (yaml.YAMLError, json.JSONDecodeError):
            continue
        for doc in docs:
            if isinstance(doc, dict):
                return doc
    return {}
