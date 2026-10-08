"""Contratos positivo, negativos e ausência de POST do preflight PC24x7 DEV."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "portfolio_bridge_preflight_dev.py"
spec = importlib.util.spec_from_file_location("portfolio_bridge_preflight", MODULE)
assert spec and spec.loader
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

REPO = "ericson-j-santos/portal-portabilidade"
SHA = "a" * 40


class Transport:
    def __init__(self):
        self.requests = []
        self.health = {
            "status": "healthy", "auth_configured": True,
            "expected_rules_sha_configured": True,
        }
        self.lanes = [{"repository": REPO, "enabled": True, "max_in_flight": 1}]

    def request(self, service, method, url, token, data=None):
        self.requests.append((service, method, url))
        assert service == "worker"
        assert method == "GET"
        assert token == "synthetic-token"
        if url.endswith("/health"):
            return 200, self.health
        if url.endswith("/v1/repositories"):
            return 200, self.lanes
        raise AssertionError("request_forbidden")


class Facade:
    def __init__(self, transport):
        self.transport = transport
        self.source_result = {
            "state": "ready_for_dispatch",
            "repository": REPO,
            "issue_number": 13,
            "base_sha": SHA,
            "dispatched": False,
        }
        self.calls = []

    def _allowed_worker_url(self, url):
        if url != "http://127.0.0.1:8097":
            raise ValueError("invalid_url")
        return url

    def _token_from_file(self, filename):
        assert filename
        return "synthetic-token"

    def JsonTransport(self):
        return self.transport

    def run_page(self, **kwargs):
        self.calls.append(kwargs)
        assert kwargs["execute"] is False
        assert kwargs["environment"] == "dev"
        return self.source_result


@pytest.fixture
def env(tmp_path):
    values = {
        "PORTFOLIO_ENV": "dev",
        "PORTFOLIO_WORKER_URL": "http://127.0.0.1:8097",
        "PORTFOLIO_TODO_PAGE_ID": "example-private-page",
        "PORTFOLIO_TODO_DATA_SOURCE_ID": "example-data-source",
        "WORKER_POOL_SHA": SHA,
    }
    for name in preflight.TOKEN_FILES:
        path = tmp_path / name
        path.write_text("synthetic-token", encoding="utf-8")
        values[name] = str(path)
    return values


def test_positive_checks_independent_source_and_lane_without_dispatch(env):
    transport = Transport()
    facade = Facade(transport)
    result = preflight.probe(env, hostname="DESKTOP-PDQK954", bridge=facade)
    assert result["state"] == "read_only_preflight_passed"
    assert result["dispatched"] is False
    assert result["lane_max_in_flight"] == 1
    assert result["base_sha"] == SHA
    assert len(facade.calls) == 1
    assert [m for _, m, _ in transport.requests] == ["GET", "GET"]
    assert "synthetic-token" not in str(result)


def test_wrong_host_fails_before_any_network_or_file_access(env):
    facade = Facade(Transport())
    result = preflight.probe(env, hostname="NOTERI", bridge=facade)
    assert result == {"state": "blocked", "reason": "host_not_authorized", "dispatched": False}
    assert not facade.calls
    assert not facade.transport.requests


def test_dev_is_mandatory(env):
    env["PORTFOLIO_ENV"] = "prod"
    facade = Facade(Transport())
    assert preflight.probe(env, hostname=preflight.HOST, bridge=facade)["reason"] == "dev_profile_required"
    assert not facade.calls


def test_missing_token_reference_blocks_without_network(env):
    env.pop("PORTFOLIO_NOTION_TOKEN_FILE")
    facade = Facade(Transport())
    result = preflight.probe(env, hostname=preflight.HOST, bridge=facade)
    assert result["reason"] == "config_reference_missing"
    assert "PORTFOLIO_NOTION_TOKEN_FILE" in result["missing"]
    assert not facade.transport.requests


def test_missing_token_file_blocks_before_network(env):
    env["PORTFOLIO_WORKER_TOKEN_FILE"] = "/not-existent/synthetic-token"
    facade = Facade(Transport())
    result = preflight.probe(env, hostname=preflight.HOST, bridge=facade)
    assert result["reason"] == "protected_token_file_missing"
    assert "synthetic-token" not in str(result)
    assert not facade.transport.requests


def test_health_readiness_false_fails_closed(env):
    transport = Transport()
    transport.health["auth_configured"] = False
    facade = Facade(transport)
    result = preflight.probe(env, hostname=preflight.HOST, bridge=facade)
    assert result["reason"] == "worker_not_ready"
    assert not facade.calls


@pytest.mark.parametrize("lane", [
    [], [{"repository": REPO, "enabled": False, "max_in_flight": 1}],
    [{"repository": REPO, "enabled": True, "max_in_flight": 2}],
])
def test_lane_absent_disabled_or_overcapacity_fails_closed(env, lane):
    transport = Transport()
    transport.lanes = lane
    result = preflight.probe(env, hostname=preflight.HOST, bridge=Facade(transport))
    assert result["reason"] == "worker_lane_not_admitted"
    assert result["dispatched"] is False


def test_source_dry_run_must_not_dispatch(env):
    facade = Facade(Transport())
    facade.source_result["dispatched"] = True
    result = preflight.probe(env, hostname=preflight.HOST, bridge=facade)
    assert result["reason"] == "source_dry_run_not_verified"


def test_non_loopback_url_rejected_without_outbound_call(env):
    env["PORTFOLIO_WORKER_URL"] = "https://example.com"
    facade = Facade(Transport())
    result = preflight.probe(env, hostname=preflight.HOST, bridge=facade)
    assert result["reason"] == "live_read_only_preflight_failed"
    assert not facade.transport.requests


def test_wrong_worker_checkout_is_rejected(tmp_path):
    env = {
        "GITHUB_WORKSPACE": str(tmp_path),
        "WORKER_POOL_ROOT": str(tmp_path / "elsewhere"),
    }
    with pytest.raises(ValueError, match="worker_checkout_path_invalid"):
        preflight.load_bridge(env)


def test_workflow_enforces_same_repo_and_gateway_only():
    workflow = (ROOT / ".github/workflows/portfolio-bridge-preflight-dev.yml").read_text(encoding="utf-8")
    assert "runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev]" in workflow
    assert "head.repo.full_name == github.repository" in workflow
    assert "scripts\\session_launcher.py" in workflow
    assert "scripts\\command_gateway.py" in workflow
    assert '"--risk", "1"' in workflow
    assert "PORTFOLIO_ENV: dev" in workflow
    assert "--execute" not in workflow
    assert "secrets." not in workflow
