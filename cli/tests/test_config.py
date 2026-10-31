import pytest
from ace_compliance.config import (
    ACE_LOCAL_URL,
    RHG_LOCAL_URL,
    EndpointError,
    resolve_ace_url,
    resolve_profile,
    resolve_rhg_url,
)


class TestResolveProfile:
    def test_default_is_auto(self, monkeypatch):
        monkeypatch.delenv("ACE_PROFILE", raising=False)
        assert resolve_profile() == "auto"

    def test_env_used(self, monkeypatch):
        monkeypatch.setenv("ACE_PROFILE", "cloud")
        assert resolve_profile() == "cloud"

    def test_explicit_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("ACE_PROFILE", "cloud")
        assert resolve_profile("local") == "local"

    def test_case_insensitive(self):
        assert resolve_profile("LOCAL") == "local"

    def test_unknown_profile_errors(self):
        with pytest.raises(EndpointError):
            resolve_profile("staging")


class TestResolveAceUrl:
    def test_local_ignores_stray_env(self, monkeypatch):
        monkeypatch.setenv("ACE_PROFILE", "local")
        monkeypatch.setenv("ACE_URL", "https://cloud.example.com")
        assert resolve_ace_url() == ACE_LOCAL_URL

    def test_cloud_uses_env(self, monkeypatch):
        monkeypatch.setenv("ACE_PROFILE", "cloud")
        monkeypatch.setenv("ACE_URL", "https://cloud.example.com")
        assert resolve_ace_url() == "https://cloud.example.com"

    def test_cloud_requires_env(self, monkeypatch):
        monkeypatch.setenv("ACE_PROFILE", "cloud")
        monkeypatch.delenv("ACE_URL", raising=False)
        with pytest.raises(EndpointError):
            resolve_ace_url()

    def test_auto_prefers_env(self, monkeypatch):
        monkeypatch.setenv("ACE_PROFILE", "auto")
        monkeypatch.setenv("ACE_URL", "https://cloud.example.com")
        assert resolve_ace_url() == "https://cloud.example.com"

    def test_auto_falls_back_to_local(self, monkeypatch):
        monkeypatch.delenv("ACE_PROFILE", raising=False)
        monkeypatch.delenv("ACE_URL", raising=False)
        assert resolve_ace_url() == ACE_LOCAL_URL

    def test_explicit_override_wins(self, monkeypatch):
        monkeypatch.setenv("ACE_PROFILE", "local")
        assert resolve_ace_url("local", "https://explicit.example.com") == "https://explicit.example.com"


class TestResolveRhgUrl:
    def test_local_default(self, monkeypatch):
        monkeypatch.delenv("RHG_URL", raising=False)
        assert resolve_rhg_url("local") == RHG_LOCAL_URL

    def test_cloud_requires_env(self, monkeypatch):
        monkeypatch.delenv("RHG_URL", raising=False)
        monkeypatch.delenv("ACE_URL", raising=False)
        with pytest.raises(EndpointError):
            resolve_rhg_url("cloud")

    def test_cloud_falls_back_to_ace_url(self, monkeypatch):
        monkeypatch.delenv("RHG_URL", raising=False)
        monkeypatch.setenv("ACE_URL", "https://cloud.example.com")
        assert resolve_rhg_url("cloud") == "https://cloud.example.com"

    def test_cloud_prefers_rhg_url(self, monkeypatch):
        monkeypatch.setenv("ACE_URL", "https://cloud.example.com")
        monkeypatch.setenv("RHG_URL", "https://rhg.example.com")
        assert resolve_rhg_url("cloud") == "https://rhg.example.com"

    def test_explicit_override_wins(self):
        assert resolve_rhg_url("cloud", "https://rhg.example.com") == "https://rhg.example.com"
