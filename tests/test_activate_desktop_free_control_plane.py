from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "activate_desktop_free_control_plane",
    ROOT / "scripts" / "activate_desktop_free_control_plane.py",
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_lenovo_activation_uses_existing_components_and_requires_pickup(monkeypatch, tmp_path: Path) -> None:
    calls = []
    monkeypatch.setattr(m, "source_root_and_sha", lambda sha: tmp_path)
    monkeypatch.setattr(m, "preflight", lambda source: tmp_path / "runner")
    monkeypatch.setattr(m.runner, "bootstrap", lambda **kwargs: {
        "ok": True, "runner_name": "DESKTOP-RP23OGS-runtime", "runner_running": True,
    })
    monkeypatch.setattr(m.watchdog, "default_runtime_root", lambda: tmp_path / "watchdog")
    monkeypatch.setattr(m.watchdog, "install", lambda *args, **kwargs: calls.append("install") or {
        "requires_uac_activation": True,
    })
    monkeypatch.setattr(m.uac, "launch", lambda *args, **kwargs: calls.append("uac") or {"ok": True})
    monkeypatch.setattr(m.watchdog, "task_status", lambda: {
        "exists": True, "trigger_at_startup": True, "logon_type": "S4U",
    })
    monkeypatch.setattr(m.socket, "gethostname", lambda: "DESKTOP-RP23OGS")
    result = m.activate("a" * 40)
    assert calls == ["install", "uac"]
    assert result["result"] == "CONTROL_PLANE_INSTALLED_PICKUP_PENDING"
    assert result["github_pickup_proven"] is False


def test_unverified_task_never_reports_installed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(m, "source_root_and_sha", lambda sha: tmp_path)
    monkeypatch.setattr(m, "preflight", lambda source: tmp_path / "runner")
    monkeypatch.setattr(m.runner, "bootstrap", lambda **kwargs: {
        "ok": True, "runner_name": "DESKTOP-RP23OGS-runtime", "runner_running": True,
    })
    monkeypatch.setattr(m.watchdog, "default_runtime_root", lambda: tmp_path / "watchdog")
    monkeypatch.setattr(m.watchdog, "install", lambda *args, **kwargs: {"requires_uac_activation": False})
    monkeypatch.setattr(m.watchdog, "task_status", lambda: {"exists": False})
    with pytest.raises(m.ActivationBlocked, match="atstartup_s4u_not_verified"):
        m.activate("a" * 40)
