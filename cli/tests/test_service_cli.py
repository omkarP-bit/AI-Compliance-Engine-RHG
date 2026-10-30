import base64
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from ace_compliance.cli import cli
from click.testing import CliRunner


def _post_client(response):
    client = MagicMock()
    post = AsyncMock(return_value=MagicMock(
        status_code=200, json=lambda: response, raise_for_status=lambda: None, text="",
    ))
    client.return_value.__aenter__.return_value.post = post
    return client, post


def _get_client(status=200, body=None, error=None):
    client = MagicMock()
    if error is not None:
        get = AsyncMock(side_effect=error)
    else:
        get = AsyncMock(return_value=MagicMock(
            status_code=status, json=lambda: body or {"status": "healthy"}, text="",
        ))
    client.return_value.__aenter__.return_value.get = get
    return client, get


class TestHealth:
    def setup_method(self):
        self.runner = CliRunner()

    def test_both_healthy(self):
        client, _ = _get_client()
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["health", "--profile", "local"])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_down_exits_nonzero(self):
        client, _ = _get_client(error=httpx.ConnectError("refused"))
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["health", "--via", "ace", "--profile", "local"])
        assert result.exit_code == 1
        assert "DOWN" in result.output

    def test_json_output(self):
        client, _ = _get_client()
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["health", "--profile", "local", "--output", "json"])
        assert result.exit_code == 0
        assert '"service"' in result.output

    def test_single_service(self):
        client, get = _get_client()
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            self.runner.invoke(cli, ["health", "--via", "rhg", "--profile", "local"])
        assert get.call_args.args[0] == "http://localhost:8001/health"


class TestConfig:
    def setup_method(self):
        self.runner = CliRunner()

    def test_shows_profile(self):
        result = self.runner.invoke(
            cli, ["config", "--profile", "local"], env={"ACE_URL": "https://cloud.example.com"}
        )
        assert result.exit_code == 0
        assert "profile : local" in result.output
        assert "http://localhost:8000" in result.output

    def test_cloud_missing_url_is_reported(self):
        result = self.runner.invoke(cli, ["config", "--profile", "cloud"], env={"ACE_URL": ""})
        assert result.exit_code == 0
        assert "<error:" in result.output

    def test_json_output(self):
        result = self.runner.invoke(cli, ["config", "--profile", "local", "--output", "json"])
        assert result.exit_code == 0
        assert '"profile": "local"' in result.output


class TestMutate:
    def setup_method(self):
        self.runner = CliRunner()

    def _artifact(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod")
        return f

    def test_posts_to_mutate_endpoint(self, tmp_path):
        f = self._artifact(tmp_path)
        client, post = _post_client({"patches": [{"op": "remove", "path": "/spec/securityContext"}]})
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(
                cli, ["mutate", str(f), "--profile", "local", "--finding-id", "CIS-K8S-5.2.1"]
            )
        assert result.exit_code == 0
        assert post.call_args.args[0] == "http://localhost:8000/ace/mutate"
        payload = post.call_args.kwargs["json"]
        assert payload["artifact_type"] == "kubernetes"
        assert payload["finding_ids"] == ["CIS-K8S-5.2.1"]

    def test_unparseable_artifact_errors(self, tmp_path):
        f = tmp_path / "weird.txt"
        f.write_text(":: not yaml ::")
        result = self.runner.invoke(cli, ["mutate", str(f), "--profile", "local"])
        assert result.exit_code == 1
        assert "could not parse" in result.output


class TestScanAndMutate:
    def setup_method(self):
        self.runner = CliRunner()

    def _artifact(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod")
        return f

    def test_low_severity_passes(self, tmp_path):
        f = self._artifact(tmp_path)
        client, post = _post_client(
            {"risk_score": 1.0, "overall_severity": "LOW", "findings": [], "patches": []}
        )
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["scan-and-mutate", str(f), "--profile", "local"])
        assert result.exit_code == 0
        assert post.call_args.args[0] == "http://localhost:8000/ace/scan-and-mutate"

    def test_fail_on_triggers_nonzero(self, tmp_path):
        f = self._artifact(tmp_path)
        client, _ = _post_client(
            {"risk_score": 9.0, "overall_severity": "CRITICAL", "findings": [], "patches": []}
        )
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["scan-and-mutate", str(f), "--profile", "local"])
        assert result.exit_code == 1


class TestSubmit:
    def setup_method(self):
        self.runner = CliRunner()

    def _artifact(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod")
        return f

    def test_allow_exits_zero(self, tmp_path):
        f = self._artifact(tmp_path)
        client, post = _post_client({
            "decision": "ALLOW", "scan_id": "s1", "mutations_applied": 0,
            "mutator_retries": 0, "compatibility_verdict": "COMPATIBLE",
            "ops_notified": False, "blocking_findings": [], "patched_artifacts": [],
        })
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["submit", str(f), "--profile", "local"])
        assert result.exit_code == 0
        assert post.call_args.args[0] == "http://localhost:8001/rhg/submit"

    def test_block_exits_nonzero(self, tmp_path):
        f = self._artifact(tmp_path)
        client, _ = _post_client({
            "decision": "BLOCK", "scan_id": "s1", "blocking_findings": [
                {"rule_id": "K8S_PRIVILEGED", "severity": "CRITICAL", "message": "privileged"}
            ],
        })
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["submit", str(f), "--profile", "local"])
        assert result.exit_code == 1
        assert "BLOCK" in result.output

    def test_write_dir_writes_patched_artifacts(self, tmp_path):
        f = self._artifact(tmp_path)
        out = tmp_path / "out"
        content = base64.b64encode(b"hello: world").decode()
        client, _ = _post_client({
            "decision": "PATCHED", "scan_id": "s1", "blocking_findings": [],
            "patched_artifacts": [{"name": "fixed.yaml", "content": content, "patches_applied": ["x"]}],
        })
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(
                cli, ["submit", str(f), "--profile", "local", "--write-dir", str(out)]
            )
        assert result.exit_code == 0
        assert (out / "fixed.yaml").read_bytes() == b"hello: world"

    def test_json_output(self, tmp_path):
        f = self._artifact(tmp_path)
        client, _ = _post_client({"decision": "ALLOW", "blocking_findings": []})
        with patch("ace_compliance.service_cli.httpx.AsyncClient", client):
            result = self.runner.invoke(
                cli, ["submit", str(f), "--profile", "local", "--output", "json"]
            )
        assert result.exit_code == 0
        assert '"decision": "ALLOW"' in result.output


class TestArtifactNaming:
    """The server picks its parser from ``artifact.name``; a bare basename drops
    the directory context and GitHub Actions / Helm files fall through to the
    Kubernetes parser instead."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_dir_scan_keeps_workflow_path(self, tmp_path):
        wf = tmp_path / ".github" / "workflows" / "ci.yml"
        wf.parent.mkdir(parents=True)
        wf.write_text("name: CI\non: [push]\njobs: {}\n")
        client, post = _post_client(
            {"scan_id": "x", "overall_severity": "LOW", "findings": [], "risk_score": 0}
        )
        with patch("ace_compliance.cli.httpx.AsyncClient", client):
            self.runner.invoke(cli, ["scan", str(tmp_path), "--profile", "local"])
        artifacts = post.call_args.kwargs["json"]["artifacts"]
        assert artifacts[0]["name"] == ".github/workflows/ci.yml"
        assert artifacts[0]["type"] == "github_actions"

    def test_dir_scan_keeps_helm_templates_path(self, tmp_path):
        tpl = tmp_path / "chart" / "templates" / "deploy.yaml"
        tpl.parent.mkdir(parents=True)
        tpl.write_text("apiVersion: v1\nkind: Pod\n")
        client, post = _post_client(
            {"scan_id": "x", "overall_severity": "LOW", "findings": [], "risk_score": 0}
        )
        with patch("ace_compliance.cli.httpx.AsyncClient", client):
            self.runner.invoke(cli, ["scan", str(tmp_path), "--profile", "local"])
        artifacts = post.call_args.kwargs["json"]["artifacts"]
        assert artifacts[0]["name"] == "chart/templates/deploy.yaml"
        assert artifacts[0]["type"] == "helm"

    def test_single_file_uses_full_path(self, tmp_path, monkeypatch):
        wf = tmp_path / ".github" / "workflows" / "ci.yml"
        wf.parent.mkdir(parents=True)
        wf.write_text("name: CI\non: [push]\njobs: {}\n")
        monkeypatch.chdir(tmp_path)
        client, post = _post_client(
            {"scan_id": "x", "overall_severity": "LOW", "findings": [], "risk_score": 0}
        )
        with patch("ace_compliance.cli.httpx.AsyncClient", client):
            self.runner.invoke(cli, ["scan", ".github/workflows/ci.yml", "--profile", "local"])
        artifacts = post.call_args.kwargs["json"]["artifacts"]
        assert artifacts[0]["name"] == ".github/workflows/ci.yml"


class TestGlobalOptions:
    def setup_method(self):
        self.runner = CliRunner()

    def _artifact(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod")
        return f

    def test_group_profile_used_when_command_omits_it(self, tmp_path):
        f = self._artifact(tmp_path)
        client, post = _post_client(
            {"scan_id": "x", "overall_severity": "LOW", "findings": [], "risk_score": 0}
        )
        with patch("ace_compliance.cli.httpx.AsyncClient", client):
            result = self.runner.invoke(
                cli, ["--profile", "local", "scan", str(f)],
                env={"ACE_URL": "https://cloud.example.com"},
            )
        assert result.exit_code == 0
        assert post.call_args.args[0] == "http://localhost:8000/ace/scan"

    def test_group_output_used_when_command_omits_it(self, tmp_path):
        f = self._artifact(tmp_path)
        client, _ = _post_client({"scan_id": "x", "overall_severity": "LOW", "findings": []})
        with patch("ace_compliance.cli.httpx.AsyncClient", client):
            result = self.runner.invoke(
                cli, ["--output", "json", "--profile", "local", "scan", str(f)]
            )
        assert result.exit_code == 0
        assert '"scan_id":' in result.output

    def test_command_overrides_group(self, tmp_path):
        f = self._artifact(tmp_path)
        client, _ = _post_client({"scan_id": "x", "overall_severity": "LOW", "findings": []})
        with patch("ace_compliance.cli.httpx.AsyncClient", client):
            result = self.runner.invoke(
                cli, ["--output", "text", "--profile", "local", "scan", str(f), "--output", "json"]
            )
        assert result.exit_code == 0
        assert '"scan_id":' in result.output

    def test_quiet_scan_summary(self, tmp_path):
        f = self._artifact(tmp_path)
        client, _ = _post_client(
            {"scan_id": "x", "overall_severity": "LOW", "findings": [], "risk_score": 1.0}
        )
        with patch("ace_compliance.cli.httpx.AsyncClient", client):
            result = self.runner.invoke(cli, ["-q", "--profile", "local", "scan", str(f)])
        assert result.exit_code == 0
        assert "risk=1.0/10 findings=0" in result.output
