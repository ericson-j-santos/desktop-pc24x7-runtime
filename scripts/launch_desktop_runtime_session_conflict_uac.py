#!/usr/bin/env python3
"""Launch the bounded duplicate-listener resolver through a human-approved UAC prompt."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import resolve_desktop_runtime_session_conflict as resolver


EXPECTED_HOST = "DESKTOP-PDQK954"
CONFIRM = "LAUNCH-DESKTOP-RUNTIME-CONFLICT-UAC"


def verify_survivors(watchdog, local: Path, terminated_pid: int) -> bool:
    target = resolver.normalized(
        local / "DesktopPC24x7" / "GitHubRunner" / "bin" / "Runner.Listener.exe"
    )
    legacy_prefix = resolver.normalized(local / "ReqSys" / "Pc24x7GitHubRunner") + os.sep
    target_count = 0
    legacy_count = 0
    pids = watchdog._runner_process_ids()
    if terminated_pid in pids:
        return False
    for pid in pids:
        path = watchdog._process_executable_path(pid)
        if path is None:
            continue
        observed = resolver.normalized(path)
        if observed == target:
            target_count += 1
        elif observed.startswith(legacy_prefix):
            legacy_count += 1
    return target_count == 1 and legacy_count == 1


def build_resolver_arguments(
    script: Path, protected_pid: int, evidence_path: Path
) -> str:
    return subprocess.list2cmdline(
        [
            str(script),
            "--confirm",
            resolver.CONFIRM,
            "--expected-pid",
            str(protected_pid),
            "--evidence-file",
            str(evidence_path),
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    if args.confirm != CONFIRM:
        print(json.dumps({"ok": False, "error": "confirmation_invalid"}))
        return 2
    if os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold():
        print(json.dumps({"ok": False, "error": "host_not_allowed"}))
        return 2
    local_raw = os.environ.get("LOCALAPPDATA")
    if not local_raw:
        print(json.dumps({"ok": False, "error": "localappdata_unavailable"}))
        return 2

    local = Path(local_raw)
    watchdog = resolver.load_watchdog()
    try:
        protected_pid = resolver.validate_and_select_pid(watchdog, local)
    except (resolver.ConflictResolutionError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 3

    evidence_path = (
        local
        / "DesktopPC24x7"
        / "ConflictResolution"
        / f"result-{protected_pid}.json"
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.unlink(missing_ok=True)

    script = Path(resolver.__file__).resolve()
    params = build_resolver_arguments(script, protected_pid, evidence_path)
    rc = int(
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            str(script.parent),
            1,
        )
    )
    if rc <= 32:
        print(json.dumps({"ok": False, "error": f"uac_launch_failed:{rc}"}))
        return 3

    deadline = time.monotonic() + max(10, min(args.timeout_seconds, 120))
    while time.monotonic() < deadline:
        if evidence_path.is_file():
            try:
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                evidence = None
            if isinstance(evidence, dict) and not evidence.get("ok"):
                print(json.dumps(evidence, sort_keys=True))
                return 3
        if verify_survivors(watchdog, local, protected_pid):
            print(
                json.dumps(
                    {
                        "ok": True,
                        "result": "duplicate_listener_terminated_via_uac",
                        "terminated_pid": protected_pid,
                        "legacy_runner_preserved": True,
                        "production_touched": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        time.sleep(1)
    print(
        json.dumps(
            {
                "ok": False,
                "result": "UAC_APPROVAL_OR_CONFLICT_RESOLUTION_PENDING",
                "protected_pid": protected_pid,
            },
            sort_keys=True,
        )
    )
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
