from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "activate_desktop_runtime_runner.py"
SPEC = importlib.util.spec_from_file_location("activate_desktop_runtime_runner", SCRIPT)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_contract_is_repo_runner_and_labels_pinned() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'EXPECTED_HOST = "DESKTOP-PDQK954"' in text
    assert 'REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"' in text
    assert 'RUNNER_NAME = "DESKTOP-PDQK954-runtime"' in text
    assert 'RUNNER_LABELS = "pc24x7,desktop-runtime,runtime-dev"' in text
    assert "ericson-j-santos/reqsys-v2-enterprise-real" not in text
    assert "REQSYS_GITHUB_RUNNER_HOME" not in text
    assert r"C:\actions-runner" not in text


def test_runner_home_is_dedicated_and_other_home_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    expected = (tmp_path / "DesktopPC24x7" / "GitHubRunner").resolve()
    assert m.default_runner_home().resolve() == expected
    assert m.discover_runner(expected) is None
    with pytest.raises(m.ActivationError, match="diretório dedicado"):
        m.discover_runner(tmp_path / "legacy-runner")


def test_runner_supply_chain_is_fixed() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'RUNNER_VERSION = "2.337.0"' in text
    assert 'RUNNER_ASSET_SHA256 = "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc"' in text
    assert "actions/runner/releases/download/" in text
    assert "runner_digest_mismatch" in text


def test_registration_tokens_are_ephemeral() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "registration-token" in text
    assert "remove-token" in text
    assert '"registration_token_persisted": False' in text
    assert '"registration_token_logged": False' in text
    assert '"remove_token_persisted": False' in text
    assert '"remove_token_logged": False' in text


def test_bootstrap_has_no_arbitrary_target_inputs() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'parser.add_argument("--repository"' not in text
    assert 'parser.add_argument("--labels"' not in text
    assert 'parser.add_argument("--runner-name"' not in text
    assert 'parser.add_argument("--token"' not in text


def test_runtime_active_requires_registry_online_and_labels() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "runner_registry_snapshot" in text
    assert "wait_runner_registry_online" in text
    assert 'repos/{REPOSITORY}/actions/runners' in text
    assert 'REQUIRED_RUNNER_LABELS = ("self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime", "runtime-dev")' in text
    assert 'state = "runner_registry_missing"' in text
    assert 'state = "runner_github_offline"' in text
    assert 'state = "runner_labels_mismatch"' in text
    assert 'state = "runtime_active"' in text


def test_new_runner_does_not_install_or_replace_legacy_watchdog() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "def install_watchdog(" not in text
    assert "install_watchdog(repo_root" not in text
    assert '"legacy_reqsys_runner_preserved": True' in text
    assert '"watchdog_task_changed": False' in text


def test_noninteractive_mode_fails_closed_before_browser_auth() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'parser.add_argument("--non-interactive-auth", action="store_true")' in text
    assert "allow_interactive=not args.non_interactive_auth" in text
    assert "allow_interactive_auth=not args.non_interactive_auth" in text
    assert "if not allow_interactive:" in text


def test_registration_repair_policy_detects_missing_or_label_mismatch() -> None:
    assert m.should_repair_registration({"present": False, "labels_ok": False}, True) is True
    assert m.should_repair_registration({"present": True, "labels_ok": False}, True) is True
    assert m.should_repair_registration({"present": True, "labels_ok": True}, True) is False
    assert m.should_repair_registration({"present": False, "labels_ok": False}, False) is False


def test_registration_token_failure_does_not_mutate_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = tmp_path / "runner"
    runner.mkdir()
    events: list[str] = []
    monkeypatch.setattr(
        m,
        "remove_token",
        lambda *a, **k: events.append("remove_token") or "R" * 24,
    )

    def registration_failure(*args, **kwargs):
        events.append("registration_token")
        raise m.ActivationError("github_runner_admin_permission_required", "blocked")

    monkeypatch.setattr(m, "registration_token", registration_failure)
    monkeypatch.setattr(m, "stop_runner", lambda root: events.append("stop"))
    with pytest.raises(
        m.ActivationError,
        match="blocked",
    ) as exc:
        m.repair_registration(
            runner,
            Path("gh"),
            allow_interactive_auth=False,
        )
    assert exc.value.state == "github_runner_admin_permission_required"
    assert events == ["remove_token", "registration_token"]
