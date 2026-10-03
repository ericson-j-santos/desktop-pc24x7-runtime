#!/usr/bin/env python3
"""Instala o supervisor de saude como tarefa Windows S4U independente do CI."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

EXPECTED_HOST = "DESKTOP-PDQK954"
TASK_FOLDER = r"\Automation"
TASK_LEAF = "DesktopPc24x7RuntimeHealthSupervisor"
TASK_NAME = TASK_FOLDER + "\\" + TASK_LEAF
CONFIRM = "INSTALL-PC24X7-RUNTIME-HEALTH-SUPERVISOR"


class InstallError(RuntimeError):
    pass


def runtime_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise InstallError("LOCALAPPDATA ausente")
    return Path(local) / "DesktopPC24x7" / "RuntimeSupervisor"


def validate_sha(value: str) -> str:
    lowered = value.casefold()
    if len(lowered) != 40 or any(ch not in "0123456789abcdef" for ch in lowered):
        raise InstallError("source_sha invalido")
    return lowered


def copy_release(source_root: Path, destination: Path) -> None:
    files = (
        "scripts/runtime_health_supervisor.py",
        "scripts/desktop_control_plane_watchdog.py",
        "config/runtime-supervisor.example.json",
    )
    for relative in files:
        source = source_root / relative
        if not source.is_file():
            raise InstallError(f"asset ausente: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def write_launcher(root: Path, release: Path, python_executable: Path) -> Path:
    launcher = root / "run-supervisor.py"
    script = release / "scripts" / "runtime_health_supervisor.py"
    config = root / "config.json"
    state = root / "state.json"
    evidence = root / "evidence.json"
    content = (
        "import subprocess\n"
        "raise SystemExit(subprocess.run([\n"
        f"    {str(python_executable)!r}, {str(script)!r},\n"
        f"    '--config', {str(config)!r}, '--state', {str(state)!r},\n"
        f"    '--evidence', {str(evidence)!r}, '--apply'\n"
        "], check=False).returncode)\n"
    )
    launcher.write_text(content, encoding="utf-8", newline="\n")
    return launcher


def register_task(python_executable: Path, launcher: Path) -> dict[str, Any]:
    try:
        import win32com.client  # type: ignore
    except ImportError as exc:
        raise InstallError("pywin32 indisponivel") from exc
    service = win32com.client.Dispatch("Schedule.Service")
    service.Connect()
    try:
        folder = service.GetFolder(TASK_FOLDER)
    except Exception:
        folder = service.GetFolder("\\").CreateFolder(TASK_FOLDER.lstrip("\\"))
    definition = service.NewTask(0)
    definition.RegistrationInfo.Description = "PC24x7 runtime health supervisor"
    definition.Settings.Enabled = True
    definition.Settings.StartWhenAvailable = True
    definition.Settings.DisallowStartIfOnBatteries = False
    definition.Settings.StopIfGoingOnBatteries = False
    definition.Settings.MultipleInstances = 2
    definition.Settings.ExecutionTimeLimit = "PT2M"
    definition.Settings.RestartCount = 3
    definition.Settings.RestartInterval = "PT1M"
    trigger = definition.Triggers.Create(8)
    trigger.Enabled = True
    trigger.Delay = "PT30S"
    trigger.Repetition.Interval = "PT1M"
    trigger.Repetition.Duration = "P9999D"
    trigger.Repetition.StopAtDurationEnd = False
    action = definition.Actions.Create(0)
    action.Path = str(python_executable)
    action.Arguments = f'"{launcher}"'
    action.WorkingDirectory = str(launcher.parent)
    principal = definition.Principal
    principal.UserId = f"{socket.gethostname()}\\{getpass.getuser()}"
    principal.LogonType = 2
    principal.RunLevel = 0
    try:
        folder.RegisterTaskDefinition(TASK_LEAF, definition, 6, principal.UserId, "", 2)
    except Exception as exc:
        if "0x80070005" in repr(exc).casefold() or "-2147024891" in repr(exc):
            raise InstallError("task_scheduler_access_denied") from exc
        raise InstallError(f"task_registration_failed:{type(exc).__name__}") from exc
    return {"task_name": TASK_NAME, "logon_type": "S4U", "interval": "PT1M"}


def task_readback() -> dict[str, Any]:
    result = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", TASK_NAME, "/XML"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    xml = result.stdout
    return {
        "exists": result.returncode == 0,
        "boot_trigger": "<BootTrigger>" in xml,
        "s4u": "<LogonType>S4U</LogonType>" in xml,
        "minute_interval": "<Interval>PT1M</Interval>" in xml,
    }


def install(source_root: Path, source_sha: str, confirm: str) -> dict[str, Any]:
    if confirm != CONFIRM:
        raise InstallError("confirmacao invalida")
    if os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold():
        raise InstallError("host nao autorizado")
    sha = validate_sha(source_sha)
    root = runtime_root()
    release = root / "releases" / sha
    copy_release(source_root.resolve(), release)
    shutil.copy2(release / "config" / "runtime-supervisor.example.json", root / "config.json")
    launcher = write_launcher(root, release, Path(sys.executable).resolve())
    registration = register_task(Path(sys.executable).resolve(), launcher)
    readback = task_readback()
    if not all(readback.values()):
        raise InstallError("task_readback_failed")
    evidence = {
        "ok": True,
        "host": EXPECTED_HOST,
        "source_sha": sha,
        "release": str(release),
        "registration": registration,
        "readback": readback,
    }
    (root / "install-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.source_root, args.source_sha, args.confirm), sort_keys=True))
        return 0
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
