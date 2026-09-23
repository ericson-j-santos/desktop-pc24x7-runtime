from __future__ import annotations
import importlib.util
import os
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
MODULE = SCRIPTS / "bootstrap_dedicated_runtime_runner.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_dedicated_runtime_runner", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_contract_is_fixed_and_separate_from_reqsys_runner() -> None:
    assert m.REPOSITORY == "ericson-j-santos/desktop-pc24x7-runtime"
    assert m.RUNNER_NAME == "DESKTOP-PDQK954-runtime"
    assert m.RUNNER_LABELS == "pc24x7,desktop-runtime,runtime-dev"
    assert "Pc24x7GitHubRunner" not in str(m.default_runner_home())


def test_github_token_is_required(monkeypatch) -> None:
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(m.BootstrapError, match="credencial governada"):
        m.github_token()


def test_registry_rejects_ambiguous_runner(monkeypatch) -> None:
    monkeypatch.setattr(
        m,
        "api_json",
        lambda *a, **k: {"runners": [
            {"name": m.RUNNER_NAME, "status": "online", "labels": []},
            {"name": m.RUNNER_NAME, "status": "online", "labels": []},
        ]},
    )
    with pytest.raises(m.BootstrapError, match="mais de um runner"):
        m.registry_snapshot("x" * 40)


def test_replay_is_idempotent(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "runner"
    monkeypatch.setattr(m, "validate_host", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m, "github_token", lambda: "x" * 40)
    monkeypatch.setattr(m, "default_runner_home", lambda: root)
    monkeypatch.setattr(m, "runner_contract", lambda path: True)
    ready = {
        "present": True,
        "status": "online",
        "busy": False,
        "labels": list(m.REQUIRED_LABELS),
        "labels_ok": True,
    }
    monkeypatch.setattr(m, "registry_snapshot", lambda token: ready)
    monkeypatch.setattr(m, "wait_online", lambda token: ready)
    monkeypatch.setattr(m.watchdog, "start_runner", lambda *a, **k: {"started": False})
    monkeypatch.setattr(m.watchdog, "runner_running", lambda *a, **k: True)
    result = m.bootstrap(source_sha="a" * 40)
    assert result["ok"] is True
    assert result["runner_registered_now"] is False
    assert result["existing_reqsys_runner_modified"] is False


def test_remote_local_divergence_fails_closed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(m, "validate_host", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m, "github_token", lambda: "x" * 40)
    monkeypatch.setattr(m, "default_runner_home", lambda: tmp_path / "runner")
    monkeypatch.setattr(m, "runner_contract", lambda path: False)
    monkeypatch.setattr(
        m,
        "registry_snapshot",
        lambda token: {"present": True, "status": "offline", "busy": False, "labels": [], "labels_ok": False},
    )
    with pytest.raises(m.BootstrapError, match="registro remoto existe"):
        m.bootstrap(source_sha="b" * 40)
