"""The published wheel must work without the server-side ``common`` package.

``ace-compliance`` is installed from PyPI into environments that do not have
the ACE services on ``PYTHONPATH``. Only ``ace admin`` needs ``common``, and it
must fail with a clear message instead of breaking every command at import.
"""

import subprocess
import sys

from ace_compliance.cli import cli
from click.testing import CliRunner


def test_cli_module_imports_without_common_package():
    code = (
        "import sys; sys.modules['common'] = None\n"
        "from ace_compliance.cli import cli\n"
        "print(cli.name)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "cli" in result.stdout or "ace" in result.stdout


def test_config_works_without_common_package(monkeypatch):
    monkeypatch.setitem(sys.modules, "common", None)
    monkeypatch.setenv("ACE_PROFILE", "local")
    result = CliRunner().invoke(cli, ["config"])
    assert result.exit_code == 0, result.output
    assert "profile" in result.output


def test_admin_reports_missing_server_package(monkeypatch):
    monkeypatch.setitem(sys.modules, "common", None)
    result = CliRunner().invoke(cli, ["admin", "org-create", "acme"])
    assert result.exit_code != 0
    assert "server package" in result.output
    assert "PYTHONPATH=services" in result.output
