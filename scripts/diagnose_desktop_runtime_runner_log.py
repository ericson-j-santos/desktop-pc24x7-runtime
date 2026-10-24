#!/usr/bin/env python3
"""Emit a secret-safe tail of the canonical desktop runner diagnostics."""
from __future__ import annotations

import json
import importlib.util
import os
import re
from pathlib import Path


SAFE_MARKERS = (
    "connected",
    "connecting",
    "connection",
    "error",
    "failed",
    "failure",
    "http response code",
    "listening for jobs",
    "runner connect",
    "session conflict",
    "unauthorized",
)
SENSITIVE_MARKERS = ("authorization", "credential", "jwt", "secret", "token")


def main() -> int:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        print(json.dumps({"ok": False, "error": "localappdata_unavailable"}))
        return 2
    runner_home = Path(local) / "DesktopPC24x7" / "GitHubRunner"
    legacy_home = Path(local) / "ReqSys" / "Pc24x7GitHubRunner"

    identities = []
    for role, home in (("desktop_runtime", runner_home), ("legacy_reqsys", legacy_home)):
        config = home / ".runner"
        safe_identity = {"role": role, "home": str(home), "present": config.is_file()}
        if config.is_file():
            payload = json.loads(config.read_text(encoding="utf-8-sig"))
            safe_identity.update(
                {
                    "agent_id": payload.get("agentId"),
                    "agent_name": payload.get("agentName"),
                    "pool_id": payload.get("poolId"),
                    "work_folder": payload.get("workFolder"),
                }
            )
        identities.append(safe_identity)

    watchdog_path = Path(__file__).with_name("desktop_control_plane_watchdog.py")
    spec = importlib.util.spec_from_file_location("runner_watchdog_diagnostics", watchdog_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("watchdog_import_failed")
    watchdog = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(watchdog)
    processes = []
    for pid in watchdog._runner_process_ids():
        executable = watchdog._process_executable_path(pid)
        processes.append({"pid": pid, "path": str(executable) if executable else None})
    candidates = list((runner_home / "_diag").glob("Runner_*.log"))
    canonical_log = runner_home / "logs" / "runner.log"
    if canonical_log.is_file():
        candidates.append(canonical_log)
    candidates = [item for item in candidates if item.is_file()]
    if not candidates:
        print(json.dumps({"ok": False, "error": "runner_log_missing"}))
        return 3

    latest = max(candidates, key=lambda item: item.stat().st_mtime_ns)
    selected: list[str] = []
    for raw in latest.read_text(encoding="utf-8", errors="replace").splitlines()[-400:]:
        lowered = raw.casefold()
        if any(marker in lowered for marker in SENSITIVE_MARKERS):
            continue
        if not any(marker in lowered for marker in SAFE_MARKERS):
            continue
        line = re.sub(r"https?://\S+", "[URL_REDACTED]", raw)
        selected.append(line[:500])
    print(
        json.dumps(
            {
                "ok": True,
                "log_name": latest.name,
                "log_modified_ns": latest.stat().st_mtime_ns,
                "events": selected[-80:],
                "runner_identities": identities,
                "listener_processes": processes,
                "same_agent_id": (
                    len(identities) == 2
                    and identities[0].get("agent_id") is not None
                    and identities[0].get("agent_id") == identities[1].get("agent_id")
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
