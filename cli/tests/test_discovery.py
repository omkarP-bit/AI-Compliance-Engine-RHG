"""Discovery rules for ``--infra`` / ``--backend`` must never mix.

``--infra`` reports only config/infra artifacts (YAML, Terraform, compose,
Dockerfiles) while ``--backend`` reports only application source code. These
tests pin that separation down at the helper and the CLI level.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from ace_compliance.cli import cli
from ace_compliance.helpers import discover_infra_paths, resolve_backend_roots
from click.testing import CliRunner

CLEAN_RESPONSE = {
    "scan_id": "abc-123",
    "pipeline_id": "cli-scan",
    "risk_score": 0.0,
    "overall_severity": "INFO",
    "findings": [],
}


class TestDiscoverInfraPaths:
    def test_finds_infra_directories_first(self, tmp_path, monkeypatch):
        (tmp_path / "k8s").mkdir()
        (tmp_path / "api").mkdir()
        monkeypatch.chdir(tmp_path)
        assert discover_infra_paths() == ["k8s"]

    def test_falls_back_to_root_infra_files(self, tmp_path, monkeypatch):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
        (tmp_path / "main.py").write_text("print('hi')\n")
        monkeypatch.chdir(tmp_path)
        assert discover_infra_paths() == ["Dockerfile"]

    def test_returns_empty_when_only_source(self, tmp_path, monkeypatch):
        (tmp_path / "main.py").write_text("print('hi')\n")
        monkeypatch.chdir(tmp_path)
        assert discover_infra_paths() == []


class TestResolveBackendRoots:
    def test_explicit_backend_path_wins(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert resolve_backend_roots(["src/app"], ["api"]) == ["src/app"]

    def test_positional_paths_are_source_roots(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert resolve_backend_roots([], ["api/main.py"]) == ["api/main.py"]

    def test_discovers_backend_directories(self, tmp_path, monkeypatch):
        (tmp_path / "api").mkdir()
        (tmp_path / "symbolic_reasoning").mkdir()
        monkeypatch.chdir(tmp_path)
        assert resolve_backend_roots([], []) == ["api", "symbolic_reasoning"]

    def test_falls_back_to_cwd_when_source_files_present(self, tmp_path, monkeypatch):
        (tmp_path / "main.py").write_text("print('hi')\n")
        monkeypatch.chdir(tmp_path)
        assert resolve_backend_roots([], []) == ["."]

    def test_returns_empty_with_nothing_to_scan(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert resolve_backend_roots([], []) == []


def _invoke_and_capture(runner, args):
    response = MagicMock(
        status_code=200,
        json=lambda: CLEAN_RESPONSE,
        raise_for_status=lambda: None,
    )
    with patch("ace_compliance.cli.httpx.AsyncClient") as mock_client:
        post = AsyncMock(return_value=response)
        mock_client.return_value.__aenter__.return_value.post = post
        result = runner.invoke(cli, args)
    return result, post


class TestScanFlagSeparation:
    def setup_method(self):
        self.runner = CliRunner()

    def test_infra_sends_only_infra_artifacts(self, tmp_path, monkeypatch):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
        (tmp_path / "main.py").write_text("print('hi')\n")
        monkeypatch.chdir(tmp_path)

        result, post = _invoke_and_capture(self.runner, ["scan", "--infra"])
        assert result.exit_code == 0, result.output
        payload = post.await_args.kwargs["json"]
        assert [a["type"] for a in payload["artifacts"]] == ["dockerfile"]
        assert payload["backend_source"] == []

    def test_backend_sends_only_source_artifacts(self, tmp_path, monkeypatch):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "main.py").write_text("print('hi')\n")
        monkeypatch.chdir(tmp_path)

        result, post = _invoke_and_capture(self.runner, ["scan", "--backend"])
        assert result.exit_code == 0, result.output
        payload = post.await_args.kwargs["json"]
        names = [a["name"] for a in payload["artifacts"]]
        assert names == ["api/main.py"]
        assert all(a["type"] == "source_code" for a in payload["artifacts"])
        assert [b["filename"] for b in payload["backend_source"]] == ["main.py"]

    def test_backend_inside_source_only_dir(self, tmp_path, monkeypatch):
        (tmp_path / "main.py").write_text("print('hi')\n")
        monkeypatch.chdir(tmp_path)

        result, post = _invoke_and_capture(self.runner, ["scan", "--backend"])
        assert result.exit_code == 0, result.output
        payload = post.await_args.kwargs["json"]
        assert [a["name"] for a in payload["artifacts"]] == ["main.py"]

    def test_backend_without_paths_sends_no_infra_artifacts(self, tmp_path, monkeypatch):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
        monkeypatch.chdir(tmp_path)

        result, _ = _invoke_and_capture(self.runner, ["scan", "--backend"])
        assert result.exit_code == 1
        assert "No supported artifacts found" in result.output
