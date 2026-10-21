"""Regression controls for module-scoped OS simulation; no host commands."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "desktop_admin_broker.py"
SPEC = importlib.util.spec_from_file_location("broker_platform_isolation", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_broker_platform_mock_preserves_native_path_and_environment(monkeypatch, tmp_path):
    native_name = os.name
    native_environment = os.environ
    original_system_root = os.environ.get("SystemRoot")
    native_path_type = type(Path())
    assert m.os is not os
    with monkeypatch.context() as scoped:
        scoped.setattr(m.os, "name", "nt" if native_name != "nt" else "posix")
        scoped.setattr(m.os, "environ", {"SystemRoot": str(tmp_path / "mock-windows")})
        assert os.name == native_name
        assert os.environ is native_environment
        assert os.environ.get("SystemRoot") == original_system_root
        assert type(Path()) is native_path_type
        evidence = Path(tmp_path) / "native-readback.txt"
        evidence.write_text("isolated", encoding="utf-8")
        assert evidence.read_text(encoding="utf-8") == "isolated"
    assert m.os.name == native_name
    assert m.os.environ is native_environment
    assert os.name == native_name


def test_component_health_rejects_other_platform_without_process_or_receipt(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(m.os, "name", "posix")
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **kw: calls.append(a))
    with pytest.raises(m.BrokerError, match="windows_component_health_requires_windows"):
        m._windows_component_health({"runtime_root": str(tmp_path)}, "portable-negative")
    assert calls == []
    assert not (tmp_path / "evidence").exists()


def test_broker_namespace_is_fresh_for_each_test():
    assert m.os is not os
    assert m.os.name == os.name
    assert m.os.environ is os.environ
