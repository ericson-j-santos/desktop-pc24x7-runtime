from __future__ import annotations

import hashlib
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
    "repair_desktop_free_control_plane",
    SCRIPTS / "repair_desktop_free_control_plane.py",
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def make_partial_installation(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    previous = "a" * 40
    runtime = tmp_path / "runtime"
    release = runtime / "releases" / previous
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    watchdog_bytes = b"# installed watchdog\n"
    uac_bytes = b"# installed uac\n"
    (scripts / "desktop_control_plane_watchdog.py").write_bytes(watchdog_bytes)
    (scripts / "desktop_control_plane_watchdog_uac_launcher.py").write_bytes(uac_bytes)
    runner_home = tmp_path / "runner"
    (runner_home / "bin").mkdir(parents=True)
    (runner_home / ".runner").write_text("opaque", encoding="utf-8")
    (runner_home / "run.cmd").write_text("@echo off\n", encoding="utf-8")
    (runner_home / "bin" / "Runner.Listener.exe").write_bytes(b"stub")
    python = tmp_path / "python.exe"
    python.write_bytes(b"")
    metadata = {
        "host": "DESKTOP-RP23OGS",
        "source_sha": previous,
        "release_root": str(release),
        "runner_home": str(runner_home),
        "python_executable": str(python),
    }
    runtime.mkdir(exist_ok=True)
    (runtime / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (runtime / "run.py").write_text("# old launcher\n", encoding="utf-8")
    expected = {
        "previous": previous,
        "watchdog_digest": digest(watchdog_bytes),
        "uac_digest": digest(uac_bytes),
        "runner_home": runner_home.resolve(),
    }
    return runtime, release, expected


def make_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    for name in m.TARGET_RELEASE_FILES:
        (scripts / name).write_text(f"# target {name}\n", encoding="utf-8")
    return source


def patch_partial_probes(monkeypatch, runtime: Path) -> None:
    monkeypatch.setattr(m.watchdog, "require_windows_desktop", lambda: "DESKTOP-RP23OGS")
    monkeypatch.setattr(m.socket, "gethostname", lambda: "DESKTOP-RP23OGS")
    monkeypatch.setattr(m.watchdog, "default_runtime_root", lambda: runtime)
    monkeypatch.setattr(m.watchdog, "task_status", lambda: {"exists": False})
    monkeypatch.setattr(m.watchdog, "validate_runner_home", lambda path: path)
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
            "labels": ["self-hosted", "Windows", "X64", "desktop-rp23ogs"],
        },
    )
    monkeypatch.setattr(
        m,
        "configure_runner_contract",
        lambda host: SimpleNamespace(runner_name="DESKTOP-RP23OGS-runtime"),
    )
    sys.modules.setdefault("win32com", SimpleNamespace(client=SimpleNamespace()))
    sys.modules.setdefault("win32com.client", SimpleNamespace())


def inspect(monkeypatch, tmp_path: Path):
    runtime, _, expected = make_partial_installation(tmp_path)
    source = make_source(tmp_path)
    patch_partial_probes(monkeypatch, runtime)
    context = m.inspect_partial_installation(
        source,
        target_sha="b" * 40,
        expected_installed_sha=expected["previous"],
        expected_watchdog_sha256=expected["watchdog_digest"],
        expected_uac_sha256=expected["uac_digest"],
    )
    return source, runtime, expected, context


def test_preflight_accepts_only_pinned_partial_state(monkeypatch, tmp_path: Path) -> None:
    _, _, _, context = inspect(monkeypatch, tmp_path)
    result = m.preflight_result(context, "b" * 40)
    assert result["result"] == "REPAIR_PREFLIGHT_OK"
    assert result["runner_id"] == 24
    assert result["runner_pids"] == [4321]
    assert result["mutation_performed"] is False
    assert result["github_pickup_proven"] is False


def test_preflight_rejects_any_existing_task(monkeypatch, tmp_path: Path) -> None:
    runtime, _, expected = make_partial_installation(tmp_path)
    source = make_source(tmp_path)
    patch_partial_probes(monkeypatch, runtime)
    monkeypatch.setattr(m.watchdog, "task_status", lambda: {"exists": True})
    with pytest.raises(m.RepairBlocked, match="existing_watchdog_task"):
        m.inspect_partial_installation(
            source,
            target_sha="b" * 40,
            expected_installed_sha=expected["previous"],
            expected_watchdog_sha256=expected["watchdog_digest"],
            expected_uac_sha256=expected["uac_digest"],
        )


def test_preflight_rejects_digest_drift(monkeypatch, tmp_path: Path) -> None:
    runtime, _, expected = make_partial_installation(tmp_path)
    source = make_source(tmp_path)
    patch_partial_probes(monkeypatch, runtime)
    with pytest.raises(m.RepairBlocked, match="installed_watchdog_digest_changed"):
        m.inspect_partial_installation(
            source,
            target_sha="b" * 40,
            expected_installed_sha=expected["previous"],
            expected_watchdog_sha256="0" * 64,
            expected_uac_sha256=expected["uac_digest"],
        )


def test_backup_and_target_release_are_idempotent(monkeypatch, tmp_path: Path) -> None:
    source, runtime, _, context = inspect(monkeypatch, tmp_path)
    backup, backup_manifest = m.create_backup(context)
    repeated_backup, repeated_manifest = m.create_backup(context)
    assert repeated_backup == backup
    assert repeated_manifest == backup_manifest
    assert not (backup / ".runner").exists()

    target, manifest = m.stage_target_release(source, runtime, "b" * 40)
    repeated_target, repeated_target_manifest = m.stage_target_release(
        source, runtime, "b" * 40
    )
    assert repeated_target == target
    assert repeated_target_manifest == manifest


def test_activation_preserves_runner_identity_and_requires_pickup(
    monkeypatch, tmp_path: Path
) -> None:
    source, runtime, _, context = inspect(monkeypatch, tmp_path)
    monkeypatch.setattr(
        m.watchdog,
        "register_boot_task",
        lambda **kwargs: {"ok": True},
    )
    ready = {
        "exists": True,
        "trigger_at_startup": True,
        "logon_type": "S4U",
    }
    monkeypatch.setattr(m.watchdog, "task_status", lambda: ready)
    monkeypatch.setattr(
        m.uac,
        "finalize_activation",
        lambda installation: {"metadata": installation["metadata"]},
    )
    monkeypatch.setattr(
        m.watchdog,
        "load_installed_metadata",
        lambda path: {
            "metadata": json.loads(path.read_text(encoding="utf-8")),
            "metadata_path": path,
        },
    )
    result = m.activate_repair(source, context, target_sha="b" * 40)
    assert result["result"] == "CONTROL_PLANE_REPAIRED_PICKUP_PENDING"
    assert result["runner_id"] == 24
    assert result["runner_process_preserved"] is True
    assert result["github_pickup_proven"] is False
    assert result["credentials_created"] is False
    assert json.loads((runtime / "metadata.json").read_text(encoding="utf-8"))[
        "source_sha"
    ] == "b" * 40


def test_failed_activation_restores_launcher_and_metadata(
    monkeypatch, tmp_path: Path
) -> None:
    source, runtime, _, context = inspect(monkeypatch, tmp_path)
    old_metadata = (runtime / "metadata.json").read_bytes()
    old_launcher = (runtime / "run.py").read_bytes()
    monkeypatch.setattr(
        m.watchdog,
        "register_boot_task",
        lambda **kwargs: (_ for _ in ()).throw(m.watchdog.WatchdogError("boom")),
    )
    with pytest.raises(m.watchdog.WatchdogError, match="boom"):
        m.activate_repair(source, context, target_sha="b" * 40)
    assert (runtime / "metadata.json").read_bytes() == old_metadata
    assert (runtime / "run.py").read_bytes() == old_launcher


def test_repair_source_contract_has_no_bootstrap_or_secret_access() -> None:
    text = (SCRIPTS / "repair_desktop_free_control_plane.py").read_text(
        encoding="utf-8"
    )
    assert "runner.bootstrap" not in text
    assert "registration-token" not in text
    assert "service" not in text.casefold()
    assert "reboot" not in text.casefold() or '"reboot_performed": False' in text
    assert '.runner").read_' not in text
    assert "TODO Gateway" not in text


def test_s4u_registration_passes_no_password_variant() -> None:
    text = (SCRIPTS / "desktop_control_plane_watchdog.py").read_text(encoding="utf-8")
    registration = text.split("folder.RegisterTaskDefinition(", 1)[1].split(")", 1)[0]
    assert "principal.UserId,\n            None,\n            TASK_LOGON_S4U" in registration
