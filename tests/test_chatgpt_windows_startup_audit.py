"""Pure-contract tests; no Windows host access or registry mutations."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest

p = Path(__file__).resolve().parents[1] / "scripts" / "chatgpt_windows_startup_audit.py"
spec = importlib.util.spec_from_file_location("startup_audit", p)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(entries=None, match=True, package=True, confirmed=True):
    return {"host_confirmed": confirmed, "entries": entries or [],
            "runner_matches_active_console": match, "package_current_user": package}


def test_approval_flags_fail_closed():
    assert module.approval_state(bytes([2, 0])) == "enabled"
    assert module.approval_state(bytes([3, 0])) == "disabled"
    assert module.approval_state(bytes([6, 0])) == "unknown"
    assert module.approval_state(None) == "unknown"


def test_positive_registered_current_user_requires_session_and_package():
    good = {"scope": "current_user", "registration": "run", "approval": "enabled"}
    assert module.classify(fixture([good])) == "startup_registration_enabled_for_current_interactive_runner"
    assert module.classify(fixture([good], match=False)).startswith("inconclusive")
    assert module.classify(fixture([good], package=None)).startswith("inconclusive")


def test_disabled_is_not_enabled():
    entry = {"scope": "current_user", "registration": "run", "approval": "disabled"}
    assert module.classify(fixture([entry])) == "registered_but_disabled_in_scanned_sources"


def test_folder_shortcut_not_verification():
    e = {"scope": "current_user", "registration": "startup_folder", "approval": "enabled"}
    assert module.classify(fixture([e])).startswith("inconclusive")


def test_package_task_only_not_verification():
    e = {"scope": "current_user", "registration": "startup_task", "approval": "enabled"}
    assert module.classify(fixture([e])).startswith("inconclusive")


def test_machine_registration_not_current_user_attestation():
    e = {"scope": "all_users", "registration": "run", "approval": "enabled"}
    assert module.classify(fixture([e])).startswith("inconclusive")


def test_missing_registration_not_automatic():
    assert module.classify(fixture([])).startswith("inconclusive")


def test_host_mismatch_is_blocking():
    assert module.classify(fixture([], confirmed=False)) == "blocked_host_mismatch"


def test_platform_context_not_authorized(monkeypatch):
    monkeypatch.setattr(module.socket, "gethostname", lambda: "WRONG-HOST")
    with pytest.raises(module.AuditBlocked, match="host_or_platform_not_authorized"):
        module.collect()


def test_no_accidental_destructive_apis():
    root = ast.parse(p.read_text(encoding="utf-8"))
    imported = [node.module for node in ast.walk(root) if isinstance(node, ast.ImportFrom)]
    imported.extend(alias.name for node in ast.walk(root) if isinstance(node, ast.Import) for alias in node.names)
    assert "subprocess" not in imported
    calls = [ast.unparse(node.func) for node in ast.walk(root) if isinstance(node, ast.Call)]
    assert all(not any(forbidden in call for forbidden in (
        "os.system", "winreg.SetValue", "winreg.Delete", "Popen", "shutdown")) for call in calls)
