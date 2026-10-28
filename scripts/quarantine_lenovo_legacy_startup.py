#!/usr/bin/env python3
"""One-time, reversible removal of the duplicate Lenovo runner Startup entry."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


HOST = "DESKTOP-RP23OGS"
SOURCE_SHA = "18fb89dc2c788d0c0e268908971c24215c4872f3"
ENTRY_SHA256 = "556606db7fff0f25b88f2d35d98d018e579c303ab918d57280b5ae79f60e0576"
STARTUP = Path(r"C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Start-RP23OGS-Runner.cmd")
QUARANTINED = STARTUP.with_name("Start-RP23OGS-Runner.cmd.disabled-" + ENTRY_SHA256[:16])
RUNTIME = Path(r"C:\Users\User\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\DesktopPC24x7\ControlPlaneWatchdog")
RUNNER = RUNTIME.parent / "GitHubRunner" / "bin" / "Runner.Listener.exe"
CONFIRM = "QUARANTINE-LENOVO-LEGACY-STARTUP"


class Blocked(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def process(pid: int) -> dict[str, Any] | None:
    import win32com.client  # type: ignore

    wmi = win32com.client.GetObject("winmgmts:")
    rows = list(wmi.ExecQuery(
        "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine "
        f"FROM Win32_Process WHERE ProcessId = {pid}"
    ))
    if len(rows) != 1:
        return None
    row = rows[0]
    return {
        "pid": int(row.ProcessId),
        "parent_pid": int(row.ParentProcessId),
        "name": str(row.Name or ""),
        "path": str(row.ExecutablePath or ""),
        "command": str(row.CommandLine or ""),
    }


def legacy_startup_commands() -> list[int]:
    """Find a still-running invocation of the exact Startup entry."""
    import win32com.client  # type: ignore

    wmi = win32com.client.GetObject("winmgmts:")
    rows = wmi.ExecQuery("SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = 'cmd.exe'")
    return [int(row.ProcessId) for row in rows
            if str(STARTUP).casefold() in str(row.CommandLine or "").casefold()]


def preflight(pid: int) -> dict[str, Any]:
    if os.name != "nt" or socket.gethostname().upper() != HOST:
        raise Blocked("host_mismatch")
    if pid < 0:
        raise Blocked("pid_invalid")
    if not STARTUP.is_file() or STARTUP.is_symlink() or QUARANTINED.exists():
        raise Blocked("startup_entry_changed_or_already_quarantined")
    if digest(STARTUP) != ENTRY_SHA256:
        raise Blocked("startup_entry_digest_changed")
    metadata = json.loads((RUNTIME / "metadata.json").read_text(encoding="utf-8"))
    if metadata.get("host", "").upper() != HOST or metadata.get("source_sha") != SOURCE_SHA:
        raise Blocked("installation_provenance_changed")
    if pid == 0:
        if legacy_startup_commands():
            raise Blocked("legacy_startup_command_still_running")
        return {"host": HOST, "source_sha": SOURCE_SHA, "duplicate_pid": None,
                "parent_pid": None, "entry_sha256": ENTRY_SHA256}
    listener = process(pid)
    if not listener or listener["name"].casefold() != "runner.listener.exe":
        raise Blocked("duplicate_listener_missing")
    if os.path.normcase(listener["path"]) != os.path.normcase(str(RUNNER)):
        raise Blocked("duplicate_listener_path_mismatch")
    parent = process(listener["parent_pid"])
    if not parent or parent["name"].casefold() != "cmd.exe":
        raise Blocked("duplicate_parent_missing")
    if str(STARTUP).casefold() not in parent["command"].casefold():
        raise Blocked("duplicate_parent_not_startup_entry")
    return {"host": HOST, "source_sha": SOURCE_SHA, "duplicate_pid": pid,
            "parent_pid": parent["pid"], "entry_sha256": ENTRY_SHA256}


def apply(pid: int) -> dict[str, Any]:
    evidence = preflight(pid)
    os.rename(STARTUP, QUARANTINED)  # Same-volume rename; never overwrites an existing file on Windows.
    if STARTUP.exists() or not QUARANTINED.is_file() or digest(QUARANTINED) != ENTRY_SHA256:
        raise Blocked("quarantine_readback_failed")
    evidence["quarantined_path"] = str(QUARANTINED)
    if pid == 0:
        evidence["duplicate_stopped"] = True
        evidence["result"] = "LEGACY_STARTUP_QUARANTINED"
        return evidence
    taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
    stopped = subprocess.run([str(taskkill), "/PID", str(pid), "/T"],
                             capture_output=True, text=True, timeout=15, check=False)
    evidence["taskkill_exit_code"] = stopped.returncode
    deadline = time.monotonic() + 10
    while process(pid) is not None and time.monotonic() < deadline:
        time.sleep(0.25)
    evidence["duplicate_stopped"] = process(pid) is None
    evidence["result"] = "LEGACY_STARTUP_QUARANTINED" if evidence["duplicate_stopped"] else "PARTIAL_DUPLICATE_STILL_RUNNING"
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-duplicate-pid", type=int, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRM:
        print(json.dumps({"result": "BLOCKED", "reason": "confirmation_invalid"}))
        return 2
    try:
        result = preflight(args.expected_duplicate_pid) if args.preflight_only else apply(args.expected_duplicate_pid)
        if args.preflight_only:
            result["result"] = "PREFLIGHT_OK"
        print(json.dumps(result, sort_keys=True))
        return 0 if result["result"] != "PARTIAL_DUPLICATE_STILL_RUNNING" else 4
    except (Blocked, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"result": "BLOCKED", "reason": str(exc)[:160]}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
