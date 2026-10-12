#!/usr/bin/env python3
"""Bounded, read-only Desktop boot/recovery preflight. Does not reboot or log on.

Only fixed Task Scheduler task names and runner service registry metadata are read.
No task action, Run command, user name, password, token or environment secret is emitted.
"""
from __future__ import annotations
import argparse
import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HOST = "DESKTOP-PDQK954"
EXPECTED_REPO = "ericson-j-santos/desktop-pc24x7-runtime"
CONFIRM = "AUDIT-DESKTOP-HEADLESS-BOOT-ONLY"
TASKS = {
    "runtime_watchdog": r"\Automation\DesktopPc24x7RuntimeWatchdog",
    "runtime_supervisor": r"\Automation\DesktopPc24x7RuntimeHealthSupervisor",
    "admin_broker": r"\Automation\DesktopPc24x7AdminBroker",
    "legacy_watchdog": r"\Automation\ReqSysDesktopControlPlaneWatchdog",
    "legacy_broker": r"\Automation\ReqSysDesktopAdminBroker",
}
SHA = re.compile(r"^[a-f0-9]{40}$")

class Blocked(RuntimeError):
    pass

def tagname(node):
    return node.tag.rsplit("}", 1)[-1]

def findfirst(parent, name):
    return next((n for n in parent.iter() if tagname(n) == name), None)

def within(node, path):
    current = node
    for name in path:
        if current is None:
            return None
        current = next((child for child in current if tagname(child) == name), None)
    return current

def xmltask(data: str) -> dict:
    """Parse only boot/persistence flags; never access task actions or credentials."""
    root = ET.fromstring(data)
    if tagname(root) != "Task":
        raise Blocked("task_xml_root_invalid")
    triggers = findfirst(root, "Triggers")
    settings = within(root, ("Settings",))
    principal = findfirst(root, "Principal")
    boot = False
    if triggers is not None:
        for node in triggers:
            if tagname(node) != "BootTrigger":
                continue
            flag = within(node, ("Enabled",))
            if flag is None or (flag.text or "").strip().casefold() == "true":
                boot = True
    enabled = within(settings, ("Enabled",)) if settings is not None else None
    task_enabled = enabled is None or (enabled.text or "").strip().casefold() == "true"
    logon = within(principal, ("LogonType",)) if principal is not None else None
    runlevel = within(principal, ("RunLevel",)) if principal is not None else None
    logon_value = (logon.text or "").strip().casefold() if logon is not None else "unknown"
    return {
        "exists": True,
        "state": "observed",
        "boot_trigger_enabled": boot,
        "task_enabled": task_enabled,
        "unattended_logon_type": logon_value in {"s4u", "serviceaccount"},
        "principal_logon_category": (
            logon_value if logon_value in {"s4u", "serviceaccount", "interactive", "password"}
            else "other_or_unknown"
        ),
        "highest_runlevel": (runlevel.text or "").strip().casefold() == "highestavailable" if runlevel is not None else False,
    }

def querytask(name: str, run=subprocess.run) -> dict:
    if name not in TASKS.values():
        raise Blocked("task_target_not_fixed")
    binary = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "schtasks.exe"
    if os.name == "nt" and not binary.is_file():
        return {"state": "query_executable_missing", "exists": None, "boot_trigger_enabled": False}
    try:
        p = run([str(binary), "/Query", "/TN", name, "/XML"], shell=False,
                capture_output=True, text=True, errors="replace", timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"state": "query_unavailable", "exists": None, "boot_trigger_enabled": False}
    if p.returncode != 0:
        # Windows may return the same error status for absent and denied tasks.
        return {"state": "missing_or_inaccessible", "exists": None, "boot_trigger_enabled": False}
    if len(p.stdout) > 262144:
        return {"state": "xml_too_large", "exists": None, "boot_trigger_enabled": False}
    try:
        return xmltask(p.stdout)
    except (ET.ParseError, Blocked):
        return {"state": "unreadable_xml", "exists": None, "boot_trigger_enabled": False}

def runner_services() -> dict:
    """Scan registry service start flags only; never read ImagePath or credentials."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services", 0, winreg.KEY_READ) as base:
            total = winreg.QueryInfoKey(base)[0]
            if total > 12000:
                return {"state": "too_many_services", "candidate_count": 0, "auto_count": 0}
            candidates = []
            for i in range(total):
                name = winreg.EnumKey(base, i)
                value = name.casefold()
                if not value.startswith("actions.runner."):
                    continue
                if not ("desktop-pc24x7-runtime" in value or "desktop-pdqk954-runtime" in value):
                    continue
                with winreg.OpenKey(base, name, 0, winreg.KEY_READ) as service:
                    try:
                        start, _ = winreg.QueryValueEx(service, "Start")
                    except (FileNotFoundError, PermissionError, OSError):
                        start = None
                candidates.append({"automatic_start": start == 2, "start_flag_known": isinstance(start, int)})
            return {"state": "observed", "candidate_count": len(candidates),
                    "auto_count": sum(c["automatic_start"] for c in candidates),
                    "ambiguous_candidates": len(candidates) != 1,
                    "all_flags_readable": all(c["start_flag_known"] for c in candidates)}
    except (ImportError, OSError, PermissionError):
        return {"state": "inaccessible", "candidate_count": 0, "auto_count": 0}

def classify(tasks: dict, services: dict) -> dict:
    def ready(label):
        item = tasks.get(label) or {}
        return (item.get("exists") is True and
                item.get("boot_trigger_enabled") is True and
                item.get("task_enabled") is True and
                item.get("unattended_logon_type") is True)
    watchdog = ready("runtime_watchdog") or ready("legacy_watchdog")
    broker = ready("admin_broker") or ready("legacy_broker")
    supervisor = ready("runtime_supervisor")
    service_auto = (services.get("state") == "observed" and
                    services.get("candidate_count") == 1 and
                    services.get("auto_count") == 1 and
                    services.get("all_flags_readable") is True)
    # The watchdog may restart the runner. Its presence alone does not prove
    # persistence or post-reboot pickup. Require an independent runner service.
    entrypoints_observed = bool(watchdog and broker and supervisor and service_auto)
    return {
        "watchdog_boot_task_observed": watchdog,
        "broker_boot_task_observed": broker,
        "supervisor_boot_task_observed": supervisor,
        "runner_auto_service_observed": service_auto,
        "headless_entrypoints_observed": entrypoints_observed,
        "unattended_reboot_authorized_by_probe": False,
        "post_reboot_recovery_proven": False,
        "reboot_allowed": False,  # No pre-boot read can prove a future E2E.
        "result": "ENTRYPOINTS_OBSERVED_NOT_POSTBOOT_PROVEN" if entrypoints_observed
                  else "HEADLESS_RECOVERY_NOT_PROVEN",
    }

def audit() -> dict:
    if (os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold()
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPO
            or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"):
        raise Blocked("identity_or_runner_context_invalid")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    source_sha = os.environ.get("GITHUB_SHA", "")
    if not run_id.isdecimal() or not SHA.fullmatch(source_sha):
        raise Blocked("github_execution_identity_invalid")
    snapshots = {key: querytask(name) for key, name in TASKS.items()}
    services = runner_services()
    decision = classify(snapshots, services)
    try:
        import ctypes.wintypes as wt
        fn = ctypes.windll.kernel32.GetTickCount64
        fn.restype = ctypes.c_ulonglong
        uptime_seconds = int(fn() // 1000)
    except (AttributeError, OSError):
        uptime_seconds = None
    return {
        "schema": "desktop-headless-readiness/v1",
        "host": EXPECTED_HOST, "source_sha": source_sha,
        "correlation_id": "desktop-headless-preflight-" + run_id,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": uptime_seconds,
        "task_readbacks": snapshots,
        "runner_service_readback": services,
        **decision,
        "environment": "local/dev",
        "secrets_read": False, "task_actions_read": False, "mutation_performed": False,
        "reboot_performed": False,
    }

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--confirm", required=True)
    args = p.parse_args()
    if args.confirm != CONFIRM:
        print(json.dumps({"result": "INVALID_FIXED_CONFIRM"}))
        return 2
    try:
        result = audit()
    except Blocked as error:
        result = {"schema": "desktop-headless-readiness/v1",
                  "result": str(error), "reboot_allowed": False,
                  "mutation_performed": False, "reboot_performed": False}
    except Exception:
        result = {"schema": "desktop-headless-readiness/v1",
                  "result": "preflight_internal_error", "reboot_allowed": False,
                  "mutation_performed": False, "reboot_performed": False}
    output = json.dumps(result, ensure_ascii=True, sort_keys=True)
    print("HEADLESS_PREFLIGHT=" + output)
    if os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_TEMP"):
        out = Path(os.environ["RUNNER_TEMP"]) / "desktop-headless-readiness.json"
        out.write_text(output + "\n", encoding="utf-8")
    # Exit 0 only for successful observation, not for autonomous reboot readiness.
    return 0 if result.get("task_readbacks") is not None else 2

if __name__ == "__main__":
    raise SystemExit(main())
