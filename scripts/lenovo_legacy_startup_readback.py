#!/usr/bin/env python3
"""Read-only verification of the Lenovo legacy Startup quarantine."""
from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import desktop_control_plane_watchdog as watchdog
import lenovo_control_plane_pickup as pickup
import quarantine_lenovo_legacy_startup as quarantine


def main() -> int:
    host = socket.gethostname().upper()
    original = quarantine.STARTUP
    disabled = quarantine.QUARANTINED
    state_path = quarantine.RUNTIME / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    metadata = json.loads((quarantine.RUNTIME / "metadata.json").read_text(encoding="utf-8"))
    try:
        runner_process = watchdog.runner_process_snapshot(Path(metadata["runner_home"]))
    except watchdog.WatchdogError as exc:
        runner_process = {"error": str(exc)}
    payload = {
        "host": host,
        "original_exists": original.exists(),
        "quarantined_exists": disabled.is_file(),
        "quarantined_sha256": hashlib.sha256(disabled.read_bytes()).hexdigest() if disabled.is_file() else None,
        "task": watchdog.task_status(),
        "task_runtime": pickup.task_runtime_readback(),
        "runner_process": runner_process,
        "state_generated_at": state.get("generated_at"),
        "state_source_sha": state.get("source_sha"),
        "state_ok": state.get("ok"),
        "runner_recovery_ok": state.get("runner_recovery_ok"),
        "runner_status": (state.get("github_runner") or {}).get("status"),
        "listener_pid": (state.get("github_runner") or {}).get("listener_pid"),
        "legacy_startup_commands": quarantine.legacy_startup_commands(),
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if (
        host == quarantine.HOST
        and not payload["original_exists"]
        and payload["quarantined_exists"]
        and payload["quarantined_sha256"] == quarantine.ENTRY_SHA256
        and payload["task"].get("trigger_at_startup") is True
        and str(payload["task"].get("logon_type")).casefold() == "s4u"
        and payload["task_runtime"].get("state") == 4
        and payload["task_runtime"].get("enabled") is True
        and len(runner_process.get("matching_pids") or []) == 1
        and not runner_process.get("unresolved_pids")
        and payload["state_source_sha"] == quarantine.SOURCE_SHA
        and payload["state_ok"] is True
        and payload["runner_recovery_ok"] is True
        and payload["runner_status"] == "process_running"
        and not payload["legacy_startup_commands"]
    ) else 3


if __name__ == "__main__":
    raise SystemExit(main())
