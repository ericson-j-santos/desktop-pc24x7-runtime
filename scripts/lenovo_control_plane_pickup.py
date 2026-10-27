#!/usr/bin/env python3
"""Produce bounded physical pickup evidence for the Lenovo free control plane."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import desktop_control_plane_watchdog as watchdog
import desktop_control_plane_watchdog_uac_launcher as uac

EXPECTED_HOST = "DESKTOP-RP23OGS"
EXPECTED_RUNNER = "DESKTOP-RP23OGS-runtime"
EXPECTED_REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
EVIDENCE_REL = "artifacts/lenovo-control-plane-pickup/evidence.json"


class PickupBlocked(RuntimeError):
    pass


def require_sha(value: str, reason: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 40 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise PickupBlocked(reason)
    return normalized


def task_runtime_readback() -> dict[str, Any]:
    try:
        import win32com.client  # type: ignore
    except ImportError as exc:
        raise PickupBlocked("pywin32_required") from exc
    try:
        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        task = service.GetFolder(watchdog.TASK_FOLDER).GetTask(watchdog.TASK_LEAF)
    except Exception as exc:
        raise PickupBlocked("task_runtime_readback_failed") from exc
    try:
        root = ET.fromstring(str(task.Xml))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        command = root.findtext(".//t:Actions/t:Exec/t:Command", default="", namespaces=ns)
        arguments = root.findtext(".//t:Actions/t:Exec/t:Arguments", default="", namespaces=ns)
        working = root.findtext(
            ".//t:Actions/t:Exec/t:WorkingDirectory", default="", namespaces=ns
        )
        launcher = Path(arguments.strip().strip('"')).resolve()
        working_directory = Path(working).resolve()
    except (ET.ParseError, OSError, ValueError) as exc:
        raise PickupBlocked("task_action_readback_failed") from exc
    if (
        not Path(command).is_file()
        or not launcher.is_file()
        or launcher.name.casefold() != "run.py"
        or launcher.parent != working_directory
    ):
        raise PickupBlocked("task_action_contract_mismatch")
    return {
        "state": int(task.State),
        "last_task_result": int(task.LastTaskResult),
        "enabled": bool(task.Enabled),
        "launcher": str(launcher),
        "working_directory": str(working_directory),
    }


def load_task_bound_installation(runtime_root: Path, expected_sha: str) -> dict[str, Any]:
    metadata_path = runtime_root / "metadata.json"
    if not metadata_path.is_file() or metadata_path.is_symlink():
        raise PickupBlocked("metadata_missing")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PickupBlocked("metadata_invalid") from exc
    if not isinstance(metadata, dict):
        raise PickupBlocked("metadata_invalid")
    if require_sha(str(metadata.get("source_sha") or ""), "metadata_sha_invalid") != expected_sha:
        raise PickupBlocked("metadata_sha_mismatch")
    declared_root = Path(str(metadata.get("runtime_root") or "")).resolve()
    release_root = Path(str(metadata.get("release_root") or "")).resolve()
    runner_home = Path(str(metadata.get("runner_home") or "")).resolve()
    if declared_root != runtime_root or release_root != runtime_root / "releases" / expected_sha:
        raise PickupBlocked("metadata_runtime_contract_mismatch")
    if not (release_root / "scripts" / "desktop_control_plane_watchdog.py").is_file():
        raise PickupBlocked("release_watchdog_missing")
    return {"metadata": metadata, "runner_home": runner_home}


def read_state(runtime_root: Path, expected_sha: str) -> dict[str, Any]:
    path = runtime_root / "state.json"
    if not path.is_file() or path.is_symlink():
        raise PickupBlocked("watchdog_state_missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PickupBlocked("watchdog_state_invalid") from exc
    if not isinstance(payload, dict):
        raise PickupBlocked("watchdog_state_invalid")
    if payload.get("source_sha") != expected_sha:
        raise PickupBlocked("watchdog_state_sha_mismatch")
    if payload.get("ok") is not True or payload.get("runner_recovery_ok") is not True:
        raise PickupBlocked("watchdog_state_not_ready")
    if payload.get("rdc_required") is not False:
        raise PickupBlocked("lenovo_rdc_scope_mismatch")
    try:
        generated = datetime.fromisoformat(str(payload["generated_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise PickupBlocked("watchdog_state_time_invalid") from exc
    age = (datetime.now(timezone.utc) - generated.astimezone(timezone.utc)).total_seconds()
    if age < -5 or age > 120:
        raise PickupBlocked("watchdog_state_stale")
    runner_state = payload.get("github_runner")
    if not isinstance(runner_state, dict) or runner_state.get("status") not in {
        "process_running",
        "recovered",
    }:
        raise PickupBlocked("watchdog_runner_state_invalid")
    return payload


def collect(expected_sha: str) -> dict[str, Any]:
    expected = require_sha(expected_sha, "expected_source_sha_invalid")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise PickupBlocked("github_actions_required")
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise PickupBlocked("workflow_dispatch_required")
    if os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise PickupBlocked("repository_mismatch")
    if os.environ.get("RUNNER_NAME") != EXPECTED_RUNNER:
        raise PickupBlocked("runner_name_mismatch")
    if require_sha(os.environ.get("GITHUB_SHA", ""), "github_sha_invalid") != expected:
        raise PickupBlocked("github_sha_mismatch")
    host = socket.gethostname().upper()
    if host != EXPECTED_HOST:
        raise PickupBlocked("physical_host_mismatch")

    task = watchdog.task_status()
    if not uac.task_headless_ready(task):
        raise PickupBlocked("atstartup_s4u_not_ready")
    runtime_task = task_runtime_readback()
    if runtime_task["state"] != 4 or runtime_task["enabled"] is not True:
        raise PickupBlocked("watchdog_task_not_running")
    runtime_root = Path(runtime_task["working_directory"]).resolve()
    installation = load_task_bound_installation(runtime_root, expected)
    state = read_state(runtime_root, expected)
    process = watchdog.runner_process_snapshot(installation["runner_home"])
    pids = process.get("matching_pids") or []
    if len(pids) != 1 or process.get("unresolved_pids"):
        raise PickupBlocked("runner_process_identity_unproven")

    return {
        "ok": True,
        "result": "LENOVO_CONTROL_PLANE_PICKUP_PROVEN",
        "host": host,
        "runner_name": EXPECTED_RUNNER,
        "source_sha": expected,
        "github_run_id": str(os.environ.get("GITHUB_RUN_ID") or ""),
        "github_run_attempt": str(os.environ.get("GITHUB_RUN_ATTEMPT") or ""),
        "task": task,
        "task_runtime": runtime_task,
        "watchdog_generated_at": state["generated_at"],
        "watchdog_runner_status": state["github_runner"]["status"],
        "runner_pids": pids,
        "rdc_required": False,
        "credentials_created": False,
        "production_touched": False,
        "reboot_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()
    if str(args.evidence_file).replace("\\", "/") != EVIDENCE_REL:
        print(json.dumps({"result": "BLOCKED", "reason": "evidence_path_mismatch"}))
        return 3
    evidence_path = Path.cwd() / "artifacts" / "lenovo-control-plane-pickup" / "evidence.json"
    try:
        payload = collect(args.expected_source_sha)
    except (PickupBlocked, watchdog.WatchdogError, OSError, ValueError, json.JSONDecodeError) as exc:
        reason = str(exc)
        if not isinstance(exc, PickupBlocked) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", reason):
            reason = "pickup_dependency_or_state_error"
        run_id = str(os.environ.get("GITHUB_RUN_ID") or "")
        run_attempt = str(os.environ.get("GITHUB_RUN_ATTEMPT") or "")
        payload = {
            "schema_version": "1",
            "ok": False,
            "result": "BLOCKED",
            "reason": reason,
            "source_sha": (
                args.expected_source_sha
                if re.fullmatch(r"[0-9a-f]{40}", args.expected_source_sha)
                else ""
            ),
            "github_run_id": run_id if run_id.isdigit() else "",
            "github_run_attempt": run_attempt if run_attempt.isdigit() else "",
        }
        watchdog.atomic_json(evidence_path, payload)
        print(json.dumps(payload, sort_keys=True))
        return 3
    watchdog.atomic_json(evidence_path, payload)
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
