from __future__ import annotations
import importlib.util
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("dispatch_once_test", ROOT / "scripts/orchestrator_preflight_dispatch_once.py")
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
SHA = "a" * 40


def run(identifier, **extra):
    return {"id": identifier, "head_sha": SHA, "head_branch": m.BRANCH,
            "event": "workflow_dispatch", "run_attempt": 1, **extra}


def test_existing_attempt_is_reused_and_duplicates_rejected():
    assert m.existing_runs({"total_count": 1, "workflow_runs": [run(42)]}, SHA)[0]["id"] == 42
    with pytest.raises(m.bootstrap.BootstrapError):
        m.existing_runs({"total_count": 2, "workflow_runs": [run(42), run(43)]}, SHA)
    with pytest.raises(m.bootstrap.BootstrapError):
        m.existing_runs({"total_count": 1, "workflow_runs": [run(42, run_attempt=2)]}, SHA)


def test_latest_failed_ci_cannot_hide_behind_old_green():
    old = run(10, event="push", created_at="2026-10-28T01:00:00Z",
              repository={"full_name": m.REPOSITORY}, status="completed", conclusion="success")
    new = {**old, "id": 11, "created_at": "2026-10-28T01:01:00Z", "conclusion": "failure"}
    chosen = m.latest_ci({"total_count": 2, "workflow_runs": [old, new]}, SHA, "push")
    assert chosen["id"] == 11
    assert chosen["conclusion"] == "failure"


def test_ci_failure_prevents_dispatch(monkeypatch):
    monkeypatch.setattr(m.preflight, "require_source", lambda *a: None)
    monkeypatch.setattr(m.preflight, "require_orchestrator", lambda: None)
    monkeypatch.setattr(m.bootstrap, "validate_host", lambda: "DESKTOP-PDQK954")
    monkeypatch.setattr(m.bootstrap, "local_gh_api_json", lambda *a: {"total_count": 0, "runners": []})
    monkeypatch.setattr(m.bootstrap, "local_git_owner_token", lambda: "dummy-test-token")
    def api(path, **kwargs):
        if "/workflows/ci.yml/runs?" in path:
            item = run(10, event="push", created_at="2026-10-28T01:00:00Z",
                       repository={"full_name": m.REPOSITORY}, status="completed", conclusion="failure")
            return {"total_count": 1, "workflow_runs": [item]}
        if path.endswith("/pulls/113"):
            return {"state": "open", "draft": True, "head": {"sha": SHA}, "base": {"sha": m.MAIN}}
        if "/git/commits/" in path:
            return {"parents": [{"sha": m.PARENT}]}
        if "chatgpt-operational-rules" in path:
            return {"commit": {"sha": m.RULES}}
        return {"commit": {"sha": m.MAIN if path.endswith("/main") else SHA}}
    monkeypatch.setattr(m.bootstrap, "api_json", api)
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: pytest.fail("POST must not be sent"))
    with pytest.raises(m.bootstrap.BootstrapError) as error:
        m.dispatch(SHA, "dispatch-negative-control")
    assert error.value.state == "dispatch_latest_ci_failed"
