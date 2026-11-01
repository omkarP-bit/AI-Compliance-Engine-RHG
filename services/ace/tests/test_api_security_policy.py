"""Guard rails for the OWASP API Security Top 10 policy.

The Rego unit tests are the real coverage proof (``opa test policies/``), but
they only run where the OPA CLI is installed. These tests keep the policy
wired into ACE, make sure every OWASP API category is present, and pin the
set/object encoding that ``OPAClient`` has to unwrap.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ace.api.routes import POLICY_MAP
from ace.engine.opa_client import _unwrap_set

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICIES_DIR = REPO_ROOT / "policies"
POLICY_FILE = POLICIES_DIR / "api-security" / "deny.rego"


def test_source_code_artifacts_are_routed_to_the_api_policy():
    assert POLICY_MAP["source_code"] == "ace/api/security"
    assert POLICY_FILE.is_file()


def test_policy_covers_every_owasp_api_top_10_category():
    policy = POLICY_FILE.read_text()
    missing = [
        f"API{number}"
        for number in range(1, 11)
        if f"API-SEC-OWASP-API{number}" not in policy
    ]
    assert not missing, f"missing OWASP API Top 10 categories: {missing}"


def test_placeholder_policy_is_gone():
    policy = POLICY_FILE.read_text()
    assert "API-SEC-OPA-000" not in policy
    assert "placeholder" not in policy.lower()


def test_opa_client_unwraps_object_valued_sets():
    """OPA encodes a set of objects as ``{json_object: true}``.

    ``ace.api.security.deny`` is a partial set of finding objects, so this is
    exactly the shape the API returns and the client must decode.
    """
    finding = {
        "rule_id": "API-SEC-OWASP-API1",
        "severity": "HIGH",
        "message": "object route without ownership check",
    }
    findings = _unwrap_set({json.dumps(finding): True})
    assert findings == [finding]


def test_rego_policy_tests_pass():
    opa = shutil.which("opa")
    if not opa:
        pytest.skip("OPA CLI not installed; run `make test-opa` in CI/dev")
    result = subprocess.run(
        [opa, "test", str(POLICIES_DIR)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
