from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "upgrade_desktop_free_control_plane",
    SCRIPTS / "upgrade_desktop_free_control_plane.py",
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    for name in m.repair.TARGET_RELEASE_FILES:
        (scripts / name).write_text(f"# {name}\n", encoding="utf-8")
    return source


def context(tmp_path: Path) -> dict:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    previous = "a" * 40
    metadata = {
        "host": "DESKTOP-RP23OGS",
        "source_sha": previous,
        "release_root": str(runtime / "releases" / previous),
        "runner_home": str(tmp_path / "runner"),
        "runtime_root": str(runtime),
    }
    (runtime / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (runtime / "run.py").write_text("# broken launcher\n", encoding="utf-8")
    (runtime / "repair-evidence.json").write_text("{}", encoding="utf-8")
    return {
        "source_root": source_tree(tmp_path),
        "target_sha": "b" * 40,
        "previous_sha": previous,
        "runtime_root": runtime,
        "metadata_path": runtime / "metadata.json",
        "metadata": metadata,
        "task": {"exists": True, "trigger_at_startup": True, "logon_type": "S4U"},
        "task_runtime": {"state": 4, "enabled": True, "last_task_result": 267009},
        "runner_home": tmp_path / "runner",
        "runner_process": {"matching_pids": [4321], "unresolved_pids": []},
        "registry": {
            "present": True,
            "id": 24,
            "status": "online",
            "busy": False,
            "labels_ok": True,
        },
        "profile": SimpleNamespace(runner_name="DESKTOP-RP23OGS-runtime"),
        "launcher_sha256": m.repair.sha256_file(runtime / "run.py"),
    }


def test_apply_upgrade_starts_fixed_launcher_and_requires_pickup(
    monkeypatch, tmp_path: Path
) -> None:
    ctx = context(tmp_path)

    def start() -> dict:
        metadata = json.loads(ctx["metadata_path"].read_text(encoding="utf-8"))
        m.watchdog.atomic_json(
            ctx["runtime_root"] / "state.json",
            {
                "ok": True,
                "source_sha": metadata["source_sha"],
                "runner_recovery_ok": True,
                "rdc_required": False,
            },
        )
        return {"run_returncode": 0}

    calls: list[str] = []

    def stop(runtime_root: Path) -> dict:
        assert runtime_root == ctx["runtime_root"]
        calls.append("stop")
        return {
            "stopped": True,
            "state_before": 4,
            "state_after": 3,
            "lock_release": {"released": True, "attempts": 2},
        }

    def start_recorded() -> dict:
        calls.append("start")
        return start()

    monkeypatch.setattr(m.watchdog, "stop_watchdog_task", stop)
    monkeypatch.setattr(m.watchdog, "run_watchdog_task", start_recorded)
    monkeypatch.setattr(
        m.watchdog,
        "runner_process_snapshot",
        lambda path: {"matching_pids": [4321], "unresolved_pids": []},
    )
    monkeypatch.setattr(
        m.runner,
        "registry_snapshot",
        lambda token: {
            "present": True,
            "id": 24,
            "status": "online",
            "busy": False,
            "labels_ok": True,
        },
    )
    monkeypatch.setattr(m.watchdog, "task_status", lambda: ctx["task"])
    monkeypatch.setattr(
        m.watchdog,
        "task_runtime_snapshot",
        lambda: {"state": 4, "enabled": True, "last_task_result": 267009},
    )

    result = m.apply_upgrade(ctx, timeout_seconds=5)

    assert result["result"] == "CONTROL_PLANE_UPGRADED_PICKUP_PENDING"
    assert result["runner_process_preserved"] is True
    assert result["github_pickup_proven"] is False
    assert result["watchdog_state"]["source_sha"] == "b" * 40
    assert result["watchdog_task_handover"]["stopped"] is True
    assert calls == ["stop", "start"]
    launcher = (ctx["runtime_root"] / "run.py").read_text(encoding="utf-8")
    assert "sys.path.insert(0, str(script_dir))" in launcher
    metadata = json.loads(ctx["metadata_path"].read_text(encoding="utf-8"))
    assert metadata["source_sha"] == "b" * 40
    assert Path(metadata["runtime_root"]) == ctx["runtime_root"]
    assert metadata["headless_boot_ready"] is True
    assert (ctx["runtime_root"] / "upgrade-evidence.json").is_file()


def test_failed_upgrade_without_target_state_restores_active_files(
    monkeypatch, tmp_path: Path
) -> None:
    ctx = context(tmp_path)
    old_metadata = ctx["metadata_path"].read_bytes()
    old_launcher = (ctx["runtime_root"] / "run.py").read_bytes()
    calls: list[str] = []
    starts = 0

    def stop(runtime_root: Path) -> dict:
        assert runtime_root == ctx["runtime_root"]
        calls.append("stop")
        return {
            "stopped": True,
            "state_before": 4,
            "state_after": 3,
            "lock_release": {"released": True, "attempts": 2},
        }

    def start() -> dict:
        nonlocal starts
        starts += 1
        calls.append("start")
        if starts == 1:
            raise m.watchdog.WatchdogError("synthetic_start_failure")
        metadata = json.loads(ctx["metadata_path"].read_text(encoding="utf-8"))
        m.watchdog.atomic_json(
            ctx["runtime_root"] / "state.json",
            {
                "ok": True,
                "source_sha": metadata["source_sha"],
                "runner_recovery_ok": True,
            },
        )
        return {"run_returncode": 0}

    monkeypatch.setattr(m.watchdog, "stop_watchdog_task", stop)
    monkeypatch.setattr(m.watchdog, "run_watchdog_task", start)
    monkeypatch.setattr(
        m.watchdog,
        "task_runtime_snapshot",
        lambda: {"state": 3, "enabled": True, "last_task_result": 0},
    )

    with pytest.raises(m.watchdog.WatchdogError, match="synthetic_start_failure"):
        m.apply_upgrade(ctx, timeout_seconds=5)

    assert ctx["metadata_path"].read_bytes() == old_metadata
    assert (ctx["runtime_root"] / "run.py").read_bytes() == old_launcher
    assert calls == ["stop", "start", "start"]


def test_upgrade_contract_does_not_register_runner_task_or_credentials() -> None:
    text = (SCRIPTS / "upgrade_desktop_free_control_plane.py").read_text(
        encoding="utf-8"
    )
    assert "runner.bootstrap" not in text
    assert "register_boot_task" not in text
    assert "register_task_from_metadata" not in text
    assert "registration-token" not in text
    assert "TODO Gateway" not in text
    assert '"github_pickup_proven": False' in text
    assert "require_current_release=True" not in text
    assert 'installation["runner_home"]' not in text
