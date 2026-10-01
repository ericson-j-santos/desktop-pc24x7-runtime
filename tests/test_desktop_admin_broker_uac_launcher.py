from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
MODULE = SCRIPTS / "desktop_admin_broker_uac_launcher.py"
SPEC = importlib.util.spec_from_file_location("desktop_admin_broker_uac_launcher", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_launcher_preconditions_fail_closed() -> None:
    m.validate_launcher(
        host=m.broker.EXPECTED_HOST,
        platform="nt",
        confirm=m.LAUNCH_CONFIRM,
    )
    with pytest.raises(RuntimeError, match="host"):
        m.validate_launcher(host="Noteri", platform="nt", confirm=m.LAUNCH_CONFIRM)
    with pytest.raises(RuntimeError, match="Windows"):
        m.validate_launcher(host=m.broker.EXPECTED_HOST, platform="posix", confirm=m.LAUNCH_CONFIRM)
    with pytest.raises(RuntimeError, match="confirmação"):
        m.validate_launcher(host=m.broker.EXPECTED_HOST, platform="nt", confirm="NO")


def test_task_ready_requires_startup_s4u_highest() -> None:
    assert m.task_ready(
        {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        }
    )
    assert not m.task_ready(
        {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "limited",
            "enabled": True,
        }
    )
    assert not m.task_ready(
        {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": False,
        }
    )


def test_elevated_command_is_metadata_only(tmp_path: Path) -> None:
    installation = {
        "release_broker": tmp_path / "desktop_admin_broker.py",
        "metadata_path": tmp_path / "metadata.json",
    }
    args = m.build_elevated_arguments(installation)
    expected = subprocess.list2cmdline(
        [
            str(installation["release_broker"]),
            "register-task-com",
            "--metadata",
            str(installation["metadata_path"]),
        ]
    )
    assert args == expected
    assert "register-task-com" in args
    assert "--metadata" in args
    assert "--command" not in args
    assert "--action" not in args
    assert "password" not in args.casefold()
    assert "token" not in args.casefold()


def test_finalize_requires_verified_privileged_task(monkeypatch, tmp_path: Path) -> None:
    metadata_path = tmp_path / "metadata.json"
    installation = {
        "metadata": {
            "activation_pending": True,
            "requires_uac_activation": True,
        },
        "metadata_path": metadata_path,
    }
    written = {}
    started = {"value": False}
    monkeypatch.setattr(
        m.broker,
        "task_status",
        lambda: {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        },
    )
    monkeypatch.setattr(
        m.broker,
        "run_task",
        lambda: started.update({"value": True}) or {"run_returncode": 0},
    )
    monkeypatch.setattr(
        m.broker,
        "persist_task_activation",
        lambda path, observed, started: written.update(
            {
                "path": path,
                "payload": {
                    **installation["metadata"],
                    "admin_channel_ready": True,
                    "activation_pending": False,
                    "admin_task": observed,
                    "admin_task_start": started,
                },
            }
        )
        or written["payload"],
    )
    result = m.finalize(installation)
    assert result["metadata"]["admin_channel_ready"] is True
    assert result["metadata"]["activation_pending"] is False
    assert written["path"] == metadata_path
    assert started["value"] is True


def test_uac_launch_requires_current_physical_task_readback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    metadata_path = tmp_path / "metadata.json"
    release_broker = tmp_path / "desktop_admin_broker.py"
    python = tmp_path / "python.exe"
    release_root = tmp_path / "release"
    release_root.mkdir()
    release_broker.write_text("", encoding="utf-8")
    python.write_text("", encoding="utf-8")
    installation = {
        "metadata": {
            "activation_pending": True,
            "requires_uac_activation": True,
        },
        "metadata_path": metadata_path,
        "release_broker": release_broker,
        "python_executable": python,
        "release_root": release_root,
    }
    proven = {
        "activation_pending": False,
        "requires_uac_activation": False,
        "admin_channel_ready": True,
        "admin_task": {
            "exists": True,
            "trigger_at_startup": True,
            "logon_type": "S4U",
            "run_level": "highest",
            "enabled": True,
        },
        "admin_task_start": {"run_returncode": 0},
    }
    monkeypatch.setattr(m, "validate_launcher", lambda **kwargs: None)
    monkeypatch.setattr(m, "load_installation", lambda path: installation)
    monkeypatch.setattr(m, "is_admin", lambda: False)
    monkeypatch.setattr(m, "shell_execute_runas", lambda *args, **kwargs: 42)
    monkeypatch.setattr(
        m.broker,
        "load_installed_metadata",
        lambda path, require_current_release=False: {
            "metadata": proven,
            "metadata_path": metadata_path,
        },
    )
    monkeypatch.setattr(
        m.broker,
        "task_status",
        lambda: dict(proven["admin_task"]),
    )

    result = m.launch(metadata_path, confirm=m.LAUNCH_CONFIRM, timeout_seconds=5)

    assert result["ok"] is True
    assert result["mode"] == "uac"
    assert result["task"]["exists"] is True
    assert result["metadata"]["admin_channel_ready"] is True
