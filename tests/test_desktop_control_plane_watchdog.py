from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "desktop_control_plane_watchdog.py"
SPEC = importlib.util.spec_from_file_location("desktop_control_plane_watchdog", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def make_runner_home(tmp_path: Path) -> Path:
    root = tmp_path / "actions-runner"
    (root / "bin").mkdir(parents=True)
    (root / ".runner").write_text("opaque-config", encoding="utf-8")
    (root / "run.cmd").write_text("@echo off\n", encoding="utf-8")
    (root / "bin" / "Runner.Listener.exe").write_bytes(b"stub")
    return root


def test_launcher_adds_release_scripts_to_import_path(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    scripts = runtime / "releases" / ("a" * 40) / "scripts"
    scripts.mkdir(parents=True)
    evidence = tmp_path / "launcher-evidence.txt"
    (scripts / "pc24x7_host_policy.py").write_text(
        "MARKER = 'sibling-import-ok'\n", encoding="utf-8"
    )
    (scripts / "desktop_control_plane_watchdog.py").write_text(
        "from pathlib import Path\n"
        "from pc24x7_host_policy import MARKER\n"
        f"Path({str(evidence)!r}).write_text(MARKER, encoding='utf-8')\n",
        encoding="utf-8",
    )
    (runtime / "metadata.json").write_text(
        json.dumps({"release_root": str(scripts.parent)}), encoding="utf-8"
    )
    launcher = m._write_launcher(runtime)

    completed = subprocess.run(
        [sys.executable, str(launcher)],
        cwd=runtime,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert evidence.read_text(encoding="utf-8") == "sibling-import-ok"
    assert "sys.path.insert(0, str(script_dir))" in launcher.read_text(encoding="utf-8")


def test_rejects_other_host(monkeypatch) -> None:
    monkeypatch.setattr(m.os, "name", "nt")
    monkeypatch.setattr(m.socket, "gethostname", lambda: "UNKNOWN-HOST")
    with pytest.raises(m.WatchdogError, match="host não autorizado"):
        m.require_windows_desktop()


@pytest.mark.parametrize("host", ["DESKTOP-PDQK954", "DESKTOP-RP23OGS"])
def test_accepts_authorized_desktop_profiles(monkeypatch, host: str) -> None:
    monkeypatch.setattr(m.os, "name", "nt")
    monkeypatch.setattr(m.socket, "gethostname", lambda: host)
    assert m.require_windows_desktop() == host


def test_rejects_authorized_non_desktop_profile(monkeypatch) -> None:
    monkeypatch.setattr(m.os, "name", "nt")
    monkeypatch.setattr(m.socket, "gethostname", lambda: "NOTERI")
    with pytest.raises(m.WatchdogError, match="watchdog desktop"):
        m.require_windows_desktop()


def test_runner_home_requires_local_runner_contract(tmp_path: Path) -> None:
    root = tmp_path / "actions-runner"
    root.mkdir()
    with pytest.raises(m.WatchdogError, match="arquivos ausentes"):
        m.validate_runner_home(root)

    valid = make_runner_home(tmp_path)
    assert m.validate_runner_home(valid) == valid.resolve()


def test_runner_version_preflight_accepts_current_minimum(
    monkeypatch, tmp_path: Path
) -> None:
    runner_home = make_runner_home(tmp_path)
    observed: dict[str, object] = {}

    def fake_run(args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0, stdout="2.337.0\n", stderr="")

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    result = m.inspect_runner_version(runner_home)

    assert result["runner_version"] == "2.337.0"
    assert result["minimum_supported_runner_version"] == "2.337.0"
    assert result["runner_version_supported"] is True
    assert observed["args"][-1] == "--version"
    assert "shell" not in observed["kwargs"]


def test_runner_version_preflight_rejects_stale_runner(
    monkeypatch, tmp_path: Path
) -> None:
    runner_home = make_runner_home(tmp_path)
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, stdout="2.336.0\n", stderr=""
        ),
    )
    with pytest.raises(m.WatchdogError, match="runner_version_unsupported"):
        m.inspect_runner_version(runner_home)


def test_start_runner_rejects_unsupported_version_before_process_probe(
    monkeypatch, tmp_path: Path
) -> None:
    runner_home = make_runner_home(tmp_path)
    monkeypatch.setattr(
        m,
        "inspect_runner_version",
        lambda runner: (_ for _ in ()).throw(
            m.WatchdogError("runner_version_unsupported:2.336.0:minimum=2.337.0")
        ),
    )
    monkeypatch.setattr(
        m,
        "runner_process_snapshot",
        lambda runner: (_ for _ in ()).throw(
            AssertionError("process probe must not run for unsupported version")
        ),
    )
    with pytest.raises(m.WatchdogError, match="runner_version_unsupported"):
        m.start_runner(runner_home, tmp_path / "runner.log")


def test_discovery_prefers_explicit_runner_home(tmp_path: Path) -> None:
    valid = make_runner_home(tmp_path)
    assert m.discover_runner_home(valid) == valid.resolve()


def test_default_discovery_is_isolated_to_runtime_runner(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    expected = tmp_path / "DesktopPC24x7" / "GitHubRunner"
    assert m._candidate_runner_homes() == [expected]
    source = MODULE.read_text(encoding="utf-8")
    assert "REQSYS_GITHUB_RUNNER_HOME" not in source
    assert 'Path(r"C:\\\\actions-runner")' not in source


def test_rdc_claim_missing_is_not_healthy(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(m, "RDC_HEADLESS_CLAIM", tmp_path / "missing.json")
    assert m.read_rdc_claim() == {"fresh": False, "reason": "claim_missing"}


def test_rdc_claim_fresh_is_accepted(monkeypatch, tmp_path: Path) -> None:
    from datetime import datetime, timezone

    claim = tmp_path / "claim.json"
    claim.write_text(
        json.dumps({"ready": True, "updated_at": datetime.now(timezone.utc).isoformat()}),
        encoding="utf-8",
    )
    monkeypatch.setattr(m, "RDC_HEADLESS_CLAIM", claim)
    result = m.read_rdc_claim()
    assert result["fresh"] is True
    assert result["reason"] == "fresh"


def test_recover_rdc_skips_restart_when_claim_is_fresh(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(m, "read_rdc_claim", lambda: {"fresh": True, "reason": "fresh"})
    result = m.recover_rdc(
        python_executable=Path("python"),
        recovery_script=tmp_path / "recovery.py",
        evidence_path=tmp_path / "evidence.json",
    )
    assert result["status"] == "healthy"
    assert result["recovered"] is False


def test_recover_rdc_uses_governed_local_script(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(m, "read_rdc_claim", lambda: {"fresh": False, "reason": "stale"})
    evidence = tmp_path / "evidence.json"

    def fake_run(args, **kwargs):
        assert m.RDC_RECOVERY_CONFIRM in args
        evidence.write_text(
            json.dumps(
                {
                    "ok": True,
                    "mode": "headless_transport_proven_with_interactive_standby",
                    "owner": "headless",
                    "fallback_armed": True,
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    result = m.recover_rdc(
        python_executable=Path("python"),
        recovery_script=tmp_path / "recovery.py",
        evidence_path=evidence,
    )
    assert result["status"] == "recovered"
    assert result["fallback_armed"] is True


def test_start_runner_recovers_without_claiming_github_health(monkeypatch, tmp_path: Path) -> None:
    runner_home = make_runner_home(tmp_path)
    monkeypatch.setattr(
        m,
        "inspect_runner_version",
        lambda runner: {
            "runner_version": "2.337.0",
            "minimum_supported_runner_version": "2.337.0",
            "runner_version_supported": True,
        },
    )
    states = iter([
        {"matching_pids": [], "unresolved_pids": [], "observed": []},
        {"matching_pids": [4321], "unresolved_pids": [], "observed": []},
    ])
    monkeypatch.setattr(m, "runner_process_snapshot", lambda runner: next(states))
    monkeypatch.setattr(m, "_creationflags", lambda: 0)

    class FakeProcess:
        pid = 1234
        returncode = None

        def poll(self):
            return None

    observed = {}

    def fake_popen(args, **kwargs):
        observed["args"] = args
        observed["cwd"] = kwargs["cwd"]
        observed["env"] = kwargs["env"]
        return FakeProcess()

    monkeypatch.setenv("RUNNER_TRACKING_ID", "actions-job-tracking")
    monkeypatch.setattr(m.subprocess, "Popen", fake_popen)
    result = m.start_runner(runner_home, tmp_path / "runner.log")
    assert result["status"] == "recovered"
    assert result["launcher_pid"] == 1234
    assert result["listener_pid"] == 4321
    assert result["github_connectivity_verified"] is False
    assert result["pickup_required"] is True
    assert observed["cwd"] == str(runner_home.resolve())
    assert "run.cmd" in " ".join(str(x) for x in observed["args"])
    assert "RUNNER_TRACKING_ID" not in observed["env"]


def test_existing_listener_is_process_running_not_healthy(monkeypatch, tmp_path: Path) -> None:
    runner_home = make_runner_home(tmp_path)
    monkeypatch.setattr(
        m,
        "inspect_runner_version",
        lambda runner: {
            "runner_version": "2.337.0",
            "minimum_supported_runner_version": "2.337.0",
            "runner_version_supported": True,
        },
    )
    monkeypatch.setattr(
        m,
        "runner_process_snapshot",
        lambda runner: {"matching_pids": [2222], "unresolved_pids": [], "observed": []},
    )
    monkeypatch.setattr(
        m.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not launch")),
    )
    result = m.start_runner(runner_home, tmp_path / "runner.log")
    assert result["status"] == "process_running"
    assert result["listener_pid"] == 2222
    assert result["github_connectivity_verified"] is False
    assert result["pickup_required"] is True


def test_runner_process_snapshot_fails_closed_when_identity_is_unverifiable(
    monkeypatch, tmp_path: Path
) -> None:
    runner_home = make_runner_home(tmp_path)
    monkeypatch.setattr(m, "_runner_process_ids", lambda: [1111])
    monkeypatch.setattr(m, "_process_executable_path", lambda pid: None)
    with pytest.raises(m.WatchdogError, match="runner_listener_identity_unverifiable"):
        m.runner_process_snapshot(runner_home)


def test_restart_runner_terminates_only_exact_governed_listener(monkeypatch, tmp_path: Path) -> None:
    runner_home = make_runner_home(tmp_path)
    snapshots = iter([
        {"matching_pids": [3333], "unresolved_pids": [], "observed": []},
        {"matching_pids": [], "unresolved_pids": [], "observed": []},
        {"matching_pids": [], "unresolved_pids": [], "observed": []},
    ])
    monkeypatch.setattr(m, "runner_process_snapshot", lambda runner: next(snapshots))
    killed = []
    monkeypatch.setattr(
        m,
        "_taskkill_runner",
        lambda pid: killed.append(pid) or subprocess.CompletedProcess(["taskkill"], 0, "", ""),
    )
    monkeypatch.setattr(
        m,
        "start_runner",
        lambda *args, **kwargs: {
            "status": "recovered",
            "started": True,
            "listener_pid": 4444,
            "github_connectivity_verified": False,
            "pickup_required": True,
        },
    )
    result = m.restart_runner(runner_home, tmp_path / "runner.log")
    assert killed == [3333]
    assert result["previous_listener_pid"] == 3333
    assert result["termination_scope"] == "exact_runner_home"
    assert result["pickup_required"] is True


def test_cycle_recovers_rdc_and_runner_and_writes_sanitized_state(monkeypatch, tmp_path: Path) -> None:
    runner_home = make_runner_home(tmp_path)
    release = tmp_path / "release"
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    (scripts / m.RDC_RECOVERY_SCRIPT).write_text("# stub\n", encoding="utf-8")
    runtime = tmp_path / "runtime"

    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m, "validate_runner_home", lambda path: runner_home)
    monkeypatch.setattr(
        m,
        "recover_rdc",
        lambda **kwargs: {"status": "recovered", "recovered": True, "fallback_armed": True},
    )
    monkeypatch.setattr(
        m,
        "start_runner",
        lambda *args, **kwargs: {"status": "recovered", "started": True},
    )

    metadata = {
        "runtime_root": str(runtime),
        "release_root": str(release),
        "runner_home": str(runner_home),
        "python_executable": "python",
        "source_sha": "a" * 40,
    }
    payload = m.cycle(metadata)
    assert payload["ok"] is True
    assert payload["rdc"]["status"] == "recovered"
    assert payload["github_runner"]["status"] == "recovered"
    assert payload["production_touched"] is False
    assert payload["secrets_read"] is False
    persisted = json.loads((runtime / "state.json").read_text(encoding="utf-8"))
    assert persisted["ok"] is True


def test_lenovo_cycle_never_runs_dell_rdc(monkeypatch, tmp_path: Path) -> None:
    runner_home = make_runner_home(tmp_path)
    runtime = tmp_path / "runtime"
    monkeypatch.setattr(m, "require_windows_desktop", lambda: "DESKTOP-RP23OGS")
    monkeypatch.setattr(m, "validate_runner_home", lambda path: runner_home)
    monkeypatch.setattr(m, "recover_rdc", lambda **kwargs: pytest.fail("Dell RDC invoked on Lenovo"))
    monkeypatch.setattr(m, "start_runner", lambda *args, **kwargs: {"status": "process_running"})
    metadata = {
        "runtime_root": str(runtime), "release_root": str(tmp_path / "release"),
        "runner_home": str(runner_home), "python_executable": "python",
        "source_sha": "a" * 40,
    }
    result = m.cycle(metadata)
    assert result["ok"] is True
    assert result["rdc_required"] is False
    assert result["rdc"]["status"] == "not_applicable"
    assert result["github_pickup_required"] is True


def test_install_requires_exact_confirmation(tmp_path: Path) -> None:
    with pytest.raises(m.WatchdogError, match="confirmação inválida"):
        m.install(
            tmp_path,
            source_sha="a" * 40,
            python_executable=Path("python"),
            runner_home=None,
            runtime_root=tmp_path / "runtime",
            watch_interval_seconds=30,
            confirm="NO",
        )


def test_load_installed_metadata_binds_release_and_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setattr(m, "default_runtime_root", lambda: runtime)
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.EXPECTED_HOST)
    release = runtime / "releases" / ("a" * 40)
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    release_watchdog = scripts / "desktop_control_plane_watchdog.py"
    release_watchdog.write_text("stub", encoding="utf-8")
    python = tmp_path / "python.exe"
    python.write_text("", encoding="utf-8")
    launcher = runtime / "run.py"
    launcher.write_text("", encoding="utf-8")
    metadata = runtime / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "runtime_root": str(runtime),
                "release_root": str(release),
                "python_executable": str(python),
                "source_sha": "a" * 40,
                "host": m.EXPECTED_HOST,
            }
        ),
        encoding="utf-8",
    )
    result = m.load_installed_metadata(metadata)
    assert result["release_watchdog"] == release_watchdog.resolve()
    assert result["metadata_path"] == metadata.resolve()


def test_load_installed_metadata_rejects_release_not_bound_to_sha(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    release = runtime / "releases" / "wrong-release"
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "desktop_control_plane_watchdog.py").write_text("stub", encoding="utf-8")
    python = tmp_path / "python.exe"
    python.write_text("", encoding="utf-8")
    launcher = runtime / "run.py"
    launcher.write_text("", encoding="utf-8")
    metadata = runtime / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "runtime_root": str(runtime),
                "release_root": str(release),
                "python_executable": str(python),
                "source_sha": "a" * 40,
                "host": m.EXPECTED_HOST,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(m.WatchdogError, match="source_sha"):
        m.load_installed_metadata(metadata)


def test_install_stages_release_when_uac_activation_is_required(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "scripts").mkdir(parents=True)
    (source / "scripts" / m.RDC_RECOVERY_SCRIPT).write_text("# recovery", encoding="utf-8")
    (source / "scripts" / m.UAC_LAUNCHER_SCRIPT).write_text("# uac", encoding="utf-8")
    (source / "scripts" / m.HOST_POLICY_SCRIPT).write_text("# host policy", encoding="utf-8")
    runner = make_runner_home(tmp_path)
    runtime = tmp_path / "runtime"
    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m, "discover_runner_home", lambda explicit=None: runner.resolve())
    monkeypatch.setattr(
        m,
        "register_boot_task",
        lambda **kwargs: (_ for _ in ()).throw(m.WatchdogError("task_scheduler_access_denied")),
    )
    monkeypatch.setattr(
        m,
        "task_status",
        lambda: {"exists": False, "trigger_at_startup": False},
    )
    original_file = m.__file__
    try:
        m.__file__ = str(source / "scripts" / "desktop_control_plane_watchdog.py")
        Path(m.__file__).write_text("# watchdog", encoding="utf-8")
        result = m.install(
            source,
            source_sha="b" * 40,
            python_executable=Path(sys.executable),
            runner_home=runner,
            runtime_root=runtime,
            watch_interval_seconds=30,
            confirm=m.CONFIRM,
        )
    finally:
        m.__file__ = original_file
    assert result["ok"] is True
    assert result["headless_boot_ready"] is False
    assert result["activation_pending"] is True
    assert result["requires_uac_activation"] is True
    assert result["start"]["reason"] == "uac_activation_required"
    assert (runtime / "metadata.json").is_file()
    assert (runtime / "releases" / ("b" * 40) / "scripts" / m.UAC_LAUNCHER_SCRIPT).is_file()
    assert (runtime / "releases" / ("b" * 40) / "scripts" / m.HOST_POLICY_SCRIPT).is_file()


def test_source_contract_is_independent_of_rdc_and_github_runner(tmp_path: Path) -> None:
    text = MODULE.read_text(encoding="utf-8")
    assert 'TASK_LEAF = "DesktopPc24x7RuntimeWatchdog"' in text
    assert 'TASK_TRIGGER_BOOT = 8' in text
    assert 'TASK_LOGON_S4U = 2' in text
    assert 'SERVICE_NAME = "desktop-pc24x7-runtime-watchdog"' in text
    assert '"DesktopPC24x7" / "ControlPlaneWatchdog"' in text
    assert 'definition.Settings.RestartCount = 999' in text
    assert "pc24x7_rdc_recovery.py" in text
    assert "Runner.Listener.exe" in text
    assert "run.cmd" in text
    assert "github.com" not in text.casefold()
    assert "api.github" not in text.casefold()
    assert "workflow_dispatch" not in text
    assert "except OSError:\n            pass" not in text
    assert "except Exception:\n        pass" not in text
    assert "reboot" not in text.casefold() or '"reboot_performed": False' in text


def test_runner_config_is_validated_but_never_read() -> None:
    text = MODULE.read_text(encoding="utf-8")
    assert 'RUNNER_REQUIRED = ((".runner",), ("run.cmd",), ("bin", "Runner.Listener.exe"))' in text
    assert 'resolved.joinpath(*parts).is_file()' in text
    assert '.runner").read_' not in text


def test_register_task_cli_writes_sanitized_failure_receipt(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    metadata = tmp_path / "metadata.json"
    receipt = tmp_path / "uac-result.json"
    monkeypatch.setattr(
        m,
        "register_task_from_metadata",
        lambda path, **kwargs: (_ for _ in ()).throw(m.WatchdogError("synthetic_com_error")),
    )
    monkeypatch.setattr(m, "now_iso", lambda: "2026-10-25T20:00:00+00:00")
    monkeypatch.setattr(
        m.sys,
        "argv",
        [
            str(MODULE),
            "register-task-com",
            "--metadata",
            str(metadata),
            "--receipt",
            str(receipt),
            "--invocation-id",
            "i" * 32,
        ],
    )
    assert m.main() == 2
    output = capsys.readouterr()
    assert "synthetic_com_error" in output.err
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload == {
        "ok": False,
        "invocation_id": "i" * 32,
        "completed_at": "2026-10-25T20:00:00+00:00",
        "error": "synthetic_com_error",
        "error_type": "WatchdogError",
    }


def _scheduled_task_xml(python_executable: Path, launcher: Path) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '<RegistrationInfo><URI>\\Automation\\DesktopPc24x7RuntimeWatchdog</URI>'
        '</RegistrationInfo><Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger>'
        '</Triggers><Principals><Principal><LogonType>S4U</LogonType></Principal>'
        '</Principals><Actions><Exec>'
        f'<Command>{python_executable}</Command><Arguments>"{launcher}"</Arguments>'
        '</Exec></Actions></Task>'
    ).encode("utf-16")


def test_reconcile_quarantines_only_matching_orphan_task(
    monkeypatch, tmp_path: Path
) -> None:
    python_executable = tmp_path / "python.exe"
    launcher = tmp_path / "run.py"
    task_file = tmp_path / "System32" / "Tasks" / "Automation" / m.TASK_LEAF
    python_executable.write_bytes(b"")
    launcher.write_bytes(b"")
    task_file.parent.mkdir(parents=True)
    payload = _scheduled_task_xml(python_executable, launcher)
    task_file.write_bytes(payload)
    monkeypatch.setattr(m, "_task_file_path", lambda: task_file)
    monkeypatch.setattr(m, "task_status", lambda: {"exists": False})

    result = m._reconcile_orphaned_task_file(
        tmp_path / "runtime",
        python_executable=python_executable,
        launcher=launcher,
        invocation_id="repair-1",
    )

    assert result and result["reconciled"] is True
    assert not task_file.exists()
    backup = Path(result["backup_file"])
    assert backup.read_bytes() == payload
    manifest = json.loads((backup.parent / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["task_name"] == m.TASK_NAME
    assert manifest["invocation_id"] == "repair-1"


def test_reconcile_rejects_foreign_orphan_without_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    python_executable = tmp_path / "python.exe"
    launcher = tmp_path / "run.py"
    foreign_launcher = tmp_path / "foreign.py"
    task_file = tmp_path / "task.xml"
    for path in (python_executable, launcher, foreign_launcher):
        path.write_bytes(b"")
    payload = _scheduled_task_xml(python_executable, foreign_launcher)
    task_file.write_bytes(payload)
    monkeypatch.setattr(m, "_task_file_path", lambda: task_file)
    monkeypatch.setattr(m, "task_status", lambda: {"exists": False})

    with pytest.raises(m.WatchdogError, match="orphan_task_action_mismatch"):
        m._reconcile_orphaned_task_file(
            tmp_path / "runtime",
            python_executable=python_executable,
            launcher=launcher,
            invocation_id="repair-2",
        )
    assert task_file.read_bytes() == payload


def test_register_from_metadata_requires_elevated_readback(
    monkeypatch, tmp_path: Path
) -> None:
    metadata = tmp_path / "runtime" / "metadata.json"
    python_executable = tmp_path / "python.exe"
    launcher = tmp_path / "runtime" / "run.py"
    metadata.parent.mkdir()
    python_executable.write_bytes(b"")
    launcher.write_bytes(b"")
    monkeypatch.setattr(
        m,
        "load_installed_metadata",
        lambda path, **kwargs: {
            "runtime_root": metadata.parent,
            "python_executable": python_executable,
            "launcher": launcher,
        },
    )
    monkeypatch.setattr(m, "_reconcile_orphaned_task_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(m, "register_boot_task", lambda **kwargs: {"ok": True})
    monkeypatch.setattr(m, "task_status", lambda: {"exists": False})

    with pytest.raises(m.WatchdogError, match="task_scheduler_elevated_readback_failed"):
        m.register_task_from_metadata(metadata, invocation_id="repair-3")


def test_stop_runner_terminates_only_exact_governed_listener(monkeypatch, tmp_path: Path) -> None:
    runner_home = make_runner_home(tmp_path)
    snapshots = iter([
        {"matching_pids": [7777], "unresolved_pids": [], "observed": []},
        {"matching_pids": [], "unresolved_pids": [], "observed": []},
        {"matching_pids": [], "unresolved_pids": [], "observed": []},
    ])
    monkeypatch.setattr(m, "runner_process_snapshot", lambda runner: next(snapshots))
    killed = []
    monkeypatch.setattr(
        m,
        "_taskkill_runner",
        lambda pid: killed.append(pid) or subprocess.CompletedProcess(["taskkill"], 0, "", ""),
    )
    result = m.stop_runner(runner_home)
    assert killed == [7777]
    assert result["stopped"] is True
    assert result["previous_listener_pid"] == 7777
    assert result["termination_scope"] == "exact_runner_home"


def test_cycle_recovers_runner_even_when_rdc_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner_home = make_runner_home(tmp_path)
    release = tmp_path / "release"
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    (scripts / m.RDC_RECOVERY_SCRIPT).write_text("# stub\n", encoding="utf-8")
    runtime = tmp_path / "runtime"

    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m, "validate_runner_home", lambda path: runner_home)
    monkeypatch.setattr(
        m,
        "start_runner",
        lambda *args, **kwargs: {
            "status": "recovered",
            "started": True,
            "pickup_required": True,
        },
    )
    monkeypatch.setattr(
        m,
        "recover_rdc",
        lambda **kwargs: (_ for _ in ()).throw(m.WatchdogError("rdc_unavailable")),
    )

    payload = m.cycle(
        {
            "runtime_root": str(runtime),
            "release_root": str(release),
            "runner_home": str(runner_home),
            "python_executable": "python",
            "source_sha": "a" * 40,
        }
    )

    assert payload["runner_recovery_ok"] is True
    assert payload["github_runner"]["status"] == "recovered"
    assert payload["rdc_recovery_ok"] is False
    assert payload["rdc"]["status"] == "failed"
    assert payload["partial"] is True
    assert payload["github_pickup_required"] is True
    assert payload["ok"] is False


def test_task_security_descriptor_is_exact_and_least_privilege() -> None:
    sid = "S-1-5-21-100-200-300-1001"
    assert m.task_security_descriptor(sid) == (
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        "(A;;GRGX;;;S-1-5-21-100-200-300-1001)"
    )
    with pytest.raises(m.WatchdogError, match="task_principal_sid_invalid"):
        m.task_security_descriptor("DESKTOP\\User")


def test_register_boot_task_applies_explicit_task_sddl(
    monkeypatch, tmp_path: Path
) -> None:
    calls = {}

    class RegisteredTask:
        def SetSecurityDescriptor(self, sddl, flags):
            calls["set_security"] = (sddl, flags)

    class Folder:
        def RegisterTaskDefinition(self, *args):
            calls["register"] = args
            return RegisteredTask()

    folder = Folder()
    definition = SimpleNamespace(
        RegistrationInfo=SimpleNamespace(),
        Settings=SimpleNamespace(),
        Triggers=SimpleNamespace(Create=lambda kind: SimpleNamespace()),
        Actions=SimpleNamespace(Create=lambda kind: SimpleNamespace()),
        Principal=SimpleNamespace(),
    )

    class Service:
        def Connect(self):
            return None

        def GetFolder(self, path):
            return folder

        def NewTask(self, flags):
            return definition

    fake_client = SimpleNamespace(Dispatch=lambda name: Service())
    fake_win32com = SimpleNamespace(client=fake_client)
    monkeypatch.setitem(sys.modules, "win32com", fake_win32com)
    monkeypatch.setitem(sys.modules, "win32com.client", fake_client)
    monkeypatch.setattr(m, "require_windows_desktop", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(m, "current_user_id", lambda: "DESKTOP-RP23OGS\\User")
    monkeypatch.setattr(
        m,
        "current_user_sid",
        lambda user_id: "S-1-5-21-100-200-300-1001",
    )

    result = m.register_boot_task(
        python_executable=tmp_path / "python.exe",
        launcher=tmp_path / "run.py",
    )

    registration = calls["register"]
    assert registration[4] is None
    assert registration[5] == m.TASK_LOGON_S4U
    assert registration[6] == m.task_security_descriptor(
        "S-1-5-21-100-200-300-1001"
    )
    assert calls["set_security"] == (registration[6], 0)
    assert result["task_acl_applied"] is True
