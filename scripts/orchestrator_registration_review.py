#!/usr/bin/env python3
"""Read-only registration plan from the exact PR113 source, plus task identity."""
from __future__ import annotations
import csv
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

SOURCE_SHA = "2232022f310970df54299263f0ea93f48ee2a56a"


def parse_task(raw: bytes, task_name: str, process_sid: str | None, launcher: Path | None) -> dict:
    if len(raw) > 262144:
        raise ValueError("bounded_xml")
    xml = raw.decode("utf-16" if raw.startswith(b"\xff\xfe") or b"\x00" in raw[:80] else "utf-8-sig")
    root = ET.fromstring(xml)
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    if (root.findtext(".//t:RegistrationInfo/t:URI", namespaces=ns) or "").casefold() != task_name.casefold():
        raise ValueError("task_scope_mismatch")
    principal = root.findtext(".//t:Principal/t:UserId", default="", namespaces=ns)
    sid = principal if re.fullmatch(r"S-1-[0-9-]+", principal) else None
    arguments = root.findtext(".//t:Actions/t:Exec/t:Arguments", default="", namespaces=ns)
    return {
        "principal_sid_available": sid is not None,
        "process_sid_matches_principal": sid == process_sid if sid and process_sid else None,
        "s4u": root.findtext(".//t:Principal/t:LogonType", namespaces=ns) == "S4U",
        "boot_trigger": root.find(".//t:BootTrigger", ns) is not None,
        "action_matches_installed_launcher": (
            arguments.strip().strip('"').casefold() == str(launcher).casefold()
            if launcher is not None else None),
    }


def task_identity(watchdog, preflight) -> dict:
    report = {"scheduler_enumeration": "unavailable", "watchdog_matches": None,
              "health_supervisor_matches": None, "identity_status": "unavailable",
              "identity_source": None, "task_file_status": "not_checked"}
    who = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                         capture_output=True, timeout=10, check=False)
    match = re.search(rb"S-1-[0-9-]+", who.stdout)
    process_sid = match.group().decode("ascii") if who.returncode == 0 and match else None
    listing = subprocess.run(["schtasks.exe", "/Query", "/FO", "CSV", "/NH"],
                             capture_output=True, timeout=20, check=False)
    names = []
    if listing.returncode == 0 and len(listing.stdout) <= 1048576:
        report["scheduler_enumeration"] = "observed"
        names = [row[0] for row in csv.reader(listing.stdout.decode("utf-8-sig", errors="replace").splitlines()) if row]
    watch = [name for name in names if name.rsplit("\\", 1)[-1].casefold() == "desktoppc24x7runtimewatchdog"]
    health = [name for name in names if name.rsplit("\\", 1)[-1].casefold() == "desktoppc24x7runtimehealthsupervisor"]
    report["watchdog_matches"] = len(watch) if report["scheduler_enumeration"] == "observed" else None
    report["health_supervisor_matches"] = len(health) if report["scheduler_enumeration"] == "observed" else None
    launcher = None
    try:
        installation = watchdog.load_installed_metadata(watchdog.default_runtime_root() / "metadata.json")
        launcher = Path(installation["launcher"])
    except Exception:
        pass
    if len(watch) == 1:
        query = subprocess.run(["schtasks.exe", "/Query", "/TN", watch[0], "/XML"],
                               capture_output=True, timeout=15, check=False)
        if query.returncode == 0:
            report.update(parse_task(query.stdout, watch[0], process_sid, launcher))
            report.update(identity_status="observed", identity_source="scheduler")
            return report
    task_file = watchdog._task_file_path()
    try:
        preflight.checked_path(task_file, directory=False)
        raw = task_file.read_bytes()
        report["task_file_status"] = "present"
        report.update(parse_task(raw, watchdog.TASK_NAME, process_sid, launcher))
        report.update(identity_status="observed", identity_source="fixed_task_file_only")
    except FileNotFoundError:
        report["task_file_status"] = "not_found"
    except Exception:
        report["task_file_status"] = "unavailable"
    return report


def main() -> int:
    receipt = {"kind": "orchestrator-dev-registration-review", "source_sha": SOURCE_SHA,
               "registration_performed": False, "runner_started": False, "watchdog_changed": False}
    try:
        source = Path(os.environ["APPROVED_SOURCE_ROOT"]).resolve()
        source.relative_to(Path(r"C:\dev\chatgpt-workers").resolve())
        sys.path.insert(0, str(source / "scripts"))
        bootstrap = importlib.import_module("bootstrap_dedicated_runtime_runner")
        preflight = importlib.import_module("orchestrator_dev_runner_preflight")
        watchdog = importlib.import_module("desktop_control_plane_watchdog")
        for module in (bootstrap, preflight, watchdog):
            Path(module.__file__).resolve().relative_to(source)
        preflight.require_source(SOURCE_SHA)
        if bootstrap.validate_host().casefold() != "desktop-pdqk954":
            raise ValueError("host")
        inventory = watchdog.readonly_local_inventory()
        receipt["supervision"] = {key: inventory.get(key) for key in (
            "installed_source_sha", "metadata_status", "metadata_host_matches",
            "metadata_runner_home_matches", "metadata_release_matches",
            "state_status", "state_ok", "state_fresh_300s",
        )}
        try:
            receipt["task_identity"] = task_identity(watchdog, preflight)
        except Exception:
            receipt["task_identity"] = {"identity_status": "unavailable"}
        plan = bootstrap.orchestrator_dev_plan(
            source_sha=SOURCE_SHA, correlation_id="orchestrator-dev-registration-review-2232022f")
        receipt.update(ok=True, registration_plan=plan)
    except Exception as error:
        state = getattr(error, "state", "")
        receipt.update(ok=False, state=state if isinstance(state, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,100}", state) else "plan_readback_blocked")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
