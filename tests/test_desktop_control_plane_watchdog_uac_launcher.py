from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
MODULE = SCRIPTS / "desktop_control_plane_watchdog_uac_launcher.py"
SPEC = importlib.util.spec_from_file_location(
    "desktop_control_plane_watchdog_uac_launcher", MODULE
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


@pytest.mark.parametrize("host", ["DESKTOP-PDQK954", "DESKTOP-RP23OGS"])
def test_launcher_accepts_authorized_desktops(host: str) -> None:
    m.validate_launcher(host=host, platform="nt", confirm=m.LAUNCH_CONFIRM)


@pytest.mark.parametrize("host", ["Noteri", "UNKNOWN-HOST"])
def test_launcher_rejects_non_desktop_or_unknown_host(host: str) -> None:
    with pytest.raises(RuntimeError, match="host"):
        m.validate_launcher(host=host, platform="nt", confirm=m.LAUNCH_CONFIRM)


def test_launcher_preconditions_are_fail_closed() -> None:
    with pytest.raises(RuntimeError, match="Windows"):
        m.validate_launcher(
            host="DESKTOP-PDQK954",
            platform="posix",
            confirm=m.LAUNCH_CONFIRM,
        )
    with pytest.raises(RuntimeError, match="confirmação"):
        m.validate_launcher(host="DESKTOP-PDQK954", platform="nt", confirm="NO")


def test_task_headless_ready_requires_boot_and_s4u() -> None:
    assert m.task_headless_ready(
        {"exists": True, "trigger_at_startup": True, "logon_type": "S4U"}
    )
    assert not m.task_headless_ready(
        {"exists": True, "trigger_at_startup": False, "logon_type": "S4U"}
    )
    assert not m.task_headless_ready(
        {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "InteractiveToken",
        }
    )


def test_elevated_command_is_exact_metadata_only(tmp_path: Path) -> None:
    installation = {
        "release_watchdog": tmp_path / "desktop_control_plane_watchdog.py",
        "metadata_path": tmp_path / "metadata.json",
    }
    invocation_id = "a" * 32
    args = m.build_elevated_arguments(installation, invocation_id)
    expected = subprocess.list2cmdline(
        [
            str(installation["release_watchdog"]),
            "register-task-com",
            "--metadata",
            str(installation["metadata_path"]),
            "--receipt",
            str(tmp_path / "uac-result.json"),
            "--invocation-id",
            invocation_id,
        ]
    )
    assert args == expected
    assert "register-task-com" in args
    assert "--metadata" in args
    assert "--receipt" in args
    assert "--invocation-id" in args
    assert "--launcher" not in args
    assert "--python-executable" not in args
    assert "password" not in args.casefold()
    assert "token" not in args.casefold()


def test_matching_receipt_requires_exact_invocation(tmp_path: Path) -> None:
    receipt = tmp_path / "uac-result.json"
    receipt.write_text(
        '{"ok": false, "invocation_id": "new", "error": "com_error"}',
        encoding="utf-8",
    )
    assert m.matching_receipt(receipt, "old") is None
    assert m.matching_receipt(receipt, "new") == {
        "ok": False,
        "invocation_id": "new",
        "error": "com_error",
    }


def test_launch_surfaces_matching_elevated_failure(
    monkeypatch, tmp_path: Path
) -> None:
    installation = {
        "release_watchdog": tmp_path / "desktop_control_plane_watchdog.py",
        "metadata_path": tmp_path / "metadata.json",
        "python_executable": tmp_path / "python.exe",
        "release_root": tmp_path,
    }
    monkeypatch.setattr(m, "validate_launcher", lambda **kwargs: None)
    monkeypatch.setattr(m, "load_installation", lambda path: installation)
    monkeypatch.setattr(m.watchdog, "task_status", lambda: {"exists": False})
    monkeypatch.setattr(m, "is_admin", lambda: False)
    monkeypatch.setattr(m.watchdog, "atomic_json", lambda path, payload: None)
    monkeypatch.setattr(m, "shell_execute_runas", lambda *args: 33)
    monkeypatch.setattr(
        m.uuid,
        "uuid4",
        lambda: SimpleNamespace(hex="i" * 32),
    )
    monkeypatch.setattr(
        m,
        "matching_receipt",
        lambda path, invocation: {"ok": False, "error": "registro COM falhou"},
    )
    with pytest.raises(RuntimeError, match="uac_registration_failed:registro COM falhou"):
        m.launch(
            installation["metadata_path"],
            confirm=m.LAUNCH_CONFIRM,
            timeout_seconds=5,
        )


def test_finalize_requires_verified_task_before_start(
    monkeypatch, tmp_path: Path
) -> None:
    metadata_path = tmp_path / "metadata.json"
    installation = {
        "metadata": {
            "activation_pending": True,
            "requires_uac_activation": True,
        },
        "metadata_path": metadata_path,
    }
    started = {"value": False}
    written = {}
    monkeypatch.setattr(
        m.watchdog,
        "task_status",
        lambda: {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
        },
    )
    monkeypatch.setattr(
        m.watchdog,
        "now_iso",
        lambda: "2026-09-20T19:00:00+00:00",
    )
    monkeypatch.setattr(
        m.watchdog,
        "atomic_json",
        lambda path, payload: written.update({"path": path, "payload": payload}),
    )
    monkeypatch.setattr(
        m.watchdog,
        "run_watchdog_task",
        lambda: started.update({"value": True}) or {"run_returncode": 0},
    )
    result = m.finalize_activation(installation)
    assert result["metadata"]["headless_boot_ready"] is True
    assert result["metadata"]["activation_pending"] is False
    assert result["metadata"]["requires_uac_activation"] is False
    assert written["path"] == metadata_path
    assert started["value"] is True


def test_finalize_fails_closed_without_s4u(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        m.watchdog,
        "task_status",
        lambda: {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "InteractiveToken",
        },
    )
    with pytest.raises(RuntimeError, match="AtStartup S4U"):
        m.finalize_activation(
            {"metadata": {}, "metadata_path": tmp_path / "metadata.json"}
        )
