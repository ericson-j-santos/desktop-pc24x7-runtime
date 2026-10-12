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
            "runner_matches_active_console": match, "runner_account_matches_console_username": True,
            "package_current_user": package}


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


def test_physical_windows_workflow_uses_native_powershell():
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" /
                "chatgpt-windows-startup-readonly.yml").read_text(encoding="utf-8")
    physical = workflow.split("  physical-read:", 1)[1]
    assert physical.count("shell: powershell -NoProfile -ExecutionPolicy Bypass -File {0}") == 2
    assert "shell: pwsh" not in physical


def test_candidate_kind_distinguishes_chatgpt_codex_and_generic_openai():
    assert module.candidate_kind("OpenAI.Codex_1.2.3_x64") == "codex"
    assert module.candidate_kind("ChatGPT.exe") == "chatgpt"
    assert module.candidate_kind("OpenAI Desktop.lnk") == "openai_unresolved"
    assert module.candidate_kind("OtherApp.exe") is None


def test_console_identity_unknown_does_not_authorize_autostart():
    good = {"scope": "current_user", "registration": "run", "approval": "enabled"}
    value = fixture([good])
    value["runner_account_matches_console_username"] = None
    assert module.classify(value).startswith("inconclusive")
    value["runner_account_matches_console_username"] = False
    assert module.classify(value).startswith("inconclusive")


def test_installation_hint_not_equivalent_to_startup():
    value = fixture([])
    value["installation_candidates"] = [{"scope": "current_user", "kind": "codex",
                                          "signal": "package_registry_name_only"}]
    assert module.classify(value) == "inconclusive_installation_hint_without_enabled_startup"


def test_directory_search_reports_only_fixed_match_names(tmp_path, monkeypatch):
    appdata = tmp_path / "local"
    installed = appdata / "Programs"
    installed.mkdir(parents=True)
    (installed / "OpenAI.Codex").mkdir()
    (installed / "NonTarget").mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(appdata))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("PROGRAMDATA", raising=False)
    entries, checked = module._directory_candidates()
    assert entries == [{"scope": "user_programs", "kind": "codex",
                        "signal": "filename_only"}]
    assert "user_programs" in checked


def test_directory_scan_does_not_follow_external_symlinks(tmp_path, monkeypatch):
    local = tmp_path / "local"
    programs = local / "Programs"
    programs.mkdir(parents=True)
    target = tmp_path / "ChatGPT.exe"
    target.write_text("invalid", encoding="utf-8")
    try:
        (programs / "ChatGPT.exe").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("fixture symlinks unsupported")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    matches, _ = module._directory_candidates()
    assert all(match["kind"] != "chatgpt" for match in matches)
