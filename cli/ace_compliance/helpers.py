"""Shared CLI helpers: global-option merging, artifact discovery, and encoding."""

from __future__ import annotations

import base64
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_CHOICES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
PROFILE_CHOICES = ["local", "cloud", "auto"]

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "node",
    ".ts": "node",
    ".jsx": "node",
    ".tsx": "node",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
}
_IGNORE_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", ".next", "target", "coverage"}


class GlobalOptions:
    """Group-level defaults that individual commands may override."""

    def __init__(self, profile=None, ace_url=None, rhg_url=None, timeout=None,
                 output=None, quiet=False, verbose=False):
        self.profile = profile
        self.ace_url = ace_url
        self.rhg_url = rhg_url
        self.timeout = timeout
        self.output = output
        self.quiet = quiet
        self.verbose = verbose


def pick(*values, default=None):
    """First non-``None`` value, else ``default`` (command flag > group flag)."""
    for value in values:
        if value is not None:
            return value
    return default


def iter_artifacts(base: Path):
    seen: set[Path] = set()
    base_path = base.resolve()
    for f in base.rglob("*"):
        if not f.is_file():
            continue
        if any(part in _IGNORE_DIRS for part in f.parts):
            continue
        name = f.name.lower()
        if name.endswith((".yaml", ".yml", ".tf", ".tf.json")):
            seen.add(f.resolve())
            continue
        if "dockerfile" in name:
            seen.add(f.resolve())
            continue
        if base_path.name in {"api", "apis", "routes", "controllers", "services", "src", "app", "backend", "server", "handlers", "scripts"} or any(p in f.parts for p in {"api", "apis", "routes", "controllers", "services", "src", "app", "backend", "server", "handlers", "scripts"}):
            if f.suffix in LANGUAGE_BY_SUFFIX:
                seen.add(f.resolve())
                continue
        if f.suffix in LANGUAGE_BY_SUFFIX and (f.parent.name in {"src", "api", "app", "routes", "services"} or any(p in f.parts for p in {"src", "api", "routes", "services", "controllers"})):
            seen.add(f.resolve())
            continue
    return sorted(seen)


def infer_type(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    lower = base.lower()
    if "dockerfile" in lower:
        return "dockerfile"
    if base in (
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ) or (lower.startswith("docker-compose.") and lower.endswith((".yml", ".yaml"))):
        return "docker_compose"
    if name.endswith((".tf", ".tf.json", "tfplan.json")):
        return "terraform"
    if lower.endswith((".yaml", ".yml")):
        if ".github/workflows" in name or name.startswith("workflows/"):
            return "github_actions"
        if "templates/" in name or "/charts/" in name or lower.endswith(".tpl"):
            return "helm"
        if lower.startswith("chart.yaml"):
            return "helm"
        return "kubernetes"
    "." + lower.split(".")[-1] if "." in lower and "/" not in lower.split(".")[-1] else ""
    # For full paths
    if "." in name:
        ext_full = "." + name.lower().split(".")[-1]
        if ext_full in LANGUAGE_BY_SUFFIX:
            return "source_code"
    return "unknown"


def make_artifact(path: Path, name: str | None = None) -> dict:
    """Encode a file as an artifact.

    ``name`` is the path-aware identifier the server uses to pick a parser.
    It must keep the directory context (``.github/workflows/ci.yml``,
    ``chart/templates/deploy.yaml``) or those parsers never match.
    """
    artifact_name = name or path.name
    return {
        "type": infer_type(artifact_name),
        "name": artifact_name,
        "content": base64.b64encode(path.read_bytes()).decode(),
    }


def _display_name(path: Path, root: Path | None, given: str | None = None) -> str:
    """Path-aware artifact name.

    For a directory scan the name is relative to that directory; for a single
    file the path the user typed is kept (``./`` stripped) so parser routing
    still sees ``.github/workflows/`` or ``chart/templates/``.
    """
    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return path.name
    if given:
        cleaned = given.replace("\\", "/")
        while cleaned.startswith("./"):
            cleaned = cleaned[2:]
        return cleaned or path.name
    return path.name


def collect_artifacts(paths) -> list[dict]:
    artifacts: list[dict] = []
    for path_str in paths:
        p = Path(path_str)
        if p.is_dir():
            artifacts.extend(make_artifact(f, _display_name(f, p)) for f in iter_artifacts(p))
        else:
            artifacts.append(make_artifact(p, _display_name(p, None, path_str)))
    return artifacts


def collect_backend(paths) -> list[dict]:
    files: list[Path] = []
    for path_str in paths:
        p = Path(path_str)
        if p.is_dir():
            for f in p.rglob("*"):
                if any(part in _IGNORE_DIRS for part in f.parts):
                    continue
                if f.is_file() and f.suffix in LANGUAGE_BY_SUFFIX:
                    files.append(f)
        elif p.is_file() and p.suffix in LANGUAGE_BY_SUFFIX:
            files.append(p)
    return [_make_backend_file(f) for f in sorted(set(files))]


def _make_backend_file(path: Path) -> dict:
    return {
        "language": LANGUAGE_BY_SUFFIX.get(path.suffix, "unknown"),
        "filename": path.name,
        "content": base64.b64encode(path.read_bytes()).decode(),
    }
