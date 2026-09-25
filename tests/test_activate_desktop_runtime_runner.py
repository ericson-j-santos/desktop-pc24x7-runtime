from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
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


def test_registration_and_label_repair_policies_are_separated() -> None:
    missing = {"present": False, "labels_ok": False}
    drifted = {"present": True, "labels_ok": False}
    healthy = {"present": True, "labels_ok": True}

    assert m.should_repair_registration(missing, True) is True
    assert m.should_repair_registration(drifted, True) is False
    assert m.should_repair_labels(drifted, True) is True
    assert m.should_repair_labels(healthy, True) is False
    assert m.should_repair_labels(drifted, False) is False


def test_label_repair_adds_only_missing_custom_label_without_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, list[str]]] = []
    registry = {
        "present": True,
        "id": 42,
        "labels": ["self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime"],
        "labels_ok": False,
    }

    monkeypatch.setattr(
        m,
        "request_runner_labels",
        lambda gh, runner_id, labels: calls.append((runner_id, labels)) or True,
    )
    monkeypatch.setattr(
        m,
        "runner_registry_snapshot",
        lambda gh: {
            **registry,
            "labels": [*registry["labels"], "runtime-dev"],
            "labels_ok": True,
        },
    )

    result = m.repair_runner_labels(Path("gh"), registry, allow_interactive_auth=False)

    assert result["repaired"] is True
    assert result["added_labels"] == ["runtime-dev"]
    assert calls == [(42, ["runtime-dev"])]


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


def test_existing_runner_starts_before_github_auth_and_requires_pickup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = tmp_path / "runner"
    (runner / "bin").mkdir(parents=True)
    for relative in ("config.cmd", "run.cmd", ".runner"):
        (runner / relative).write_text("stub", encoding="utf-8")
    (runner / "bin" / "Runner.Listener.exe").write_bytes(b"stub")

    monkeypatch.setattr(m, "validate_host", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m, "resolve_source_sha", lambda *args, **kwargs: "a" * 40)
    monkeypatch.setattr(m, "discover_runner", lambda explicit=None: runner)
    monkeypatch.setattr(m, "start_runner", lambda root: True)
    monkeypatch.setattr(m, "runner_running", lambda root: True)
    monkeypatch.setattr(
        m,
        "ensure_gh",
        lambda: (_ for _ in ()).throw(
            m.ActivationError("github_auth_required", "blocked")
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--confirm",
            m.CONFIRM,
            "--source-sha",
            "a" * 40,
            "--non-interactive-auth",
        ],
    )

    code = m.main()
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    assert code == 3
    assert payload["ok"] is False
    assert payload["state"] == "listener_running_pickup_required"
    assert payload["local_recovery_ok"] is True
    assert payload["runner_running"] is True
    assert payload["github_registry_checked"] is False
    assert payload["github_pickup_required"] is True
    assert payload["github_pickup_proven"] is False


def test_failure_output_does_not_emit_raw_exception_text() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert '"error": str(exc)' not in text
    assert '"error": str(exc.reason)' not in text
