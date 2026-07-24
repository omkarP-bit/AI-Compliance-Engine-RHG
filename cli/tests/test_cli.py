from unittest.mock import AsyncMock, MagicMock, patch

from ace_compliance.cli import cli
from click.testing import CliRunner

MOCK_SCAN_RESPONSE = {
    "scan_id": "abc-123",
    "pipeline_id": "cli-scan",
    "risk_score": 7.5,
    "overall_severity": "HIGH",
    "findings": [
        {"rule_id": "CIS-K8S-5.2.1", "severity": "HIGH",
         "message": "Privileged container", "artifact": "deploy.yaml"}
    ]
}


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_scan_exits_nonzero_on_high_findings(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod")
        with patch("ace_compliance.cli.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=MagicMock(
                    status_code=200,
                    json=lambda: MOCK_SCAN_RESPONSE,
                    raise_for_status=lambda: None,
                )
            )
            result = self.runner.invoke(cli, ["scan", str(f), "--fail-on", "HIGH"])
            assert result.exit_code == 1

    def test_scan_exits_zero_on_clean_artifact(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod")
        clean_response = {**MOCK_SCAN_RESPONSE, "overall_severity": "LOW", "findings": []}
        with patch("ace_compliance.cli.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=MagicMock(
                    status_code=200,
                    json=lambda: clean_response,
                    raise_for_status=lambda: None,
                )
            )
            result = self.runner.invoke(cli, ["scan", str(f), "--fail-on", "HIGH"])
            assert result.exit_code == 0

    def test_json_output_flag(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("apiVersion: v1\nkind: Pod")
        with patch("ace_compliance.cli.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=MagicMock(
                    status_code=200,
                    json=lambda: MOCK_SCAN_RESPONSE,
                    raise_for_status=lambda: None,
                )
            )
            result = self.runner.invoke(cli, ["scan", str(f), "--output", "json"])
            assert result.exit_code == 1
            assert '"scan_id":' in result.output

    def test_scan_helps_with_no_artifacts(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = self.runner.invoke(cli, ["scan", str(empty_dir)])
        assert result.exit_code == 1
        assert "No supported artifacts found" in result.output
