from __future__ import annotations
import importlib.util
import subprocess
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("git_credential_bootstrap_test", ROOT / "scripts/bootstrap_dedicated_runtime_runner.py")
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

REGISTRY = "/repos/ericson-j-santos/reqsys-engineering-orchestrator/actions/runners?per_page=100"


def test_owner_verified_existing_credential_is_not_exported(monkeypatch):
    secret = "dummy-test-token-never-log"
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "host=github.com\npassword=" + secret + "\n", "")
    monkeypatch.setattr(m.subprocess, "run", run)
    monkeypatch.setattr(m, "api_json", lambda path, **kwargs: {"login": "ericson-j-santos"})
    assert m.local_git_owner_token() == secret
    assert calls[0][1]["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert calls[0][1]["env"]["GCM_INTERACTIVE"] == "Never"
    assert "GH_TOKEN" not in calls[0][1]["env"]
    assert "GITHUB_TOKEN" not in calls[0][1]["env"]
    assert "reqsys-engineering-orchestrator.git" in calls[0][1]["input"]


def test_other_owner_rejected_without_token_in_error(monkeypatch):
    secret = "dummy-test-token-never-log"
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "host=github.com\npassword=" + secret + "\n", ""))
    monkeypatch.setattr(m, "api_json", lambda *a, **k: {"login": "another-user"})
    with pytest.raises(m.BootstrapError) as error:
        m.local_git_owner_token()
    assert error.value.state == "github_local_auth_required"
    assert secret not in str(error.value)


@pytest.mark.parametrize("path,method", [
    ("/repos/another/repo/actions/runners?per_page=100", "GET"),
    ("/repos/ericson-j-santos/desktop-pc24x7-runtime/actions/runners?per_page=100", "GET"),
    (REGISTRY, "DELETE"),
])
def test_fallback_scope_rejected_before_credentials(monkeypatch, path, method):
    monkeypatch.setattr(m, "local_git_owner_token", lambda: pytest.fail("credential must not be accessed"))
    with pytest.raises(m.BootstrapError):
        m.local_git_api_json(path, method=method)


def test_missing_gh_uses_fixed_dev_fallback(monkeypatch):
    monkeypatch.setattr(m, "find_gh", lambda: None)
    monkeypatch.setattr(m, "local_git_api_json", lambda path, **kwargs: {"path": path})
    assert m.local_gh_api_json(REGISTRY) == {"path": REGISTRY}


def test_endpoint_error_does_not_export_secret(monkeypatch):
    secret = "dummy-test-token-never-log"
    monkeypatch.setattr(m, "local_git_owner_token", lambda: secret)
    def fail(*a, **k):
        raise m.BootstrapError("api_failed", secret)
    monkeypatch.setattr(m, "api_json", fail)
    with pytest.raises(m.BootstrapError) as error:
        m.local_git_api_json(REGISTRY)
    assert error.value.state == "github_local_api_failed"
    assert secret not in str(error.value)
