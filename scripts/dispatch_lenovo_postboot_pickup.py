#!/usr/bin/env python3
"""One exact GitHub CLI pickup for the installed Lenovo control-plane SHA."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import lenovo_control_plane_pickup as pickup
import quarantine_lenovo_legacy_startup as quarantine


REPO = "ericson-j-santos/desktop-pc24x7-runtime"
REF = "evidence/lenovo-postboot-pickup-18fb89dc-20261028"
WORKFLOW = "dedicated-runtime-runner-e2e.yml"
CONFIRM = "DISPATCH-ONE-LENOVO-POSTBOOT-PICKUP"


class Blocked(RuntimeError):
    pass


def gh(*args: str, allow_missing: bool = False) -> dict:
    exe = shutil.which("gh")
    if not exe:
        raise Blocked("github_cli_missing")
    cp = subprocess.run([exe, *args], capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=30,
                        check=False, shell=False)
    if cp.returncode:
        if allow_missing and "HTTP 404" in cp.stderr:
            return {}
        raise Blocked("github_cli_or_api_failed")
    if not cp.stdout.strip():
        return {}
    try:
        result = json.loads(cp.stdout)
    except json.JSONDecodeError as exc:
        raise Blocked("github_api_response_invalid") from exc
    if not isinstance(result, dict):
        raise Blocked("github_api_response_invalid")
    return result


def preflight() -> dict:
    if os.name != "nt" or socket.gethostname().upper() != quarantine.HOST:
        raise Blocked("host_mismatch")
    metadata = json.loads((quarantine.RUNTIME / "metadata.json").read_text(encoding="utf-8"))
    state = json.loads((quarantine.RUNTIME / "state.json").read_text(encoding="utf-8"))
    if metadata.get("source_sha") != quarantine.SOURCE_SHA or state.get("source_sha") != quarantine.SOURCE_SHA:
        raise Blocked("installed_source_sha_mismatch")
    if state.get("ok") is not True or state.get("runner_recovery_ok") is not True:
        raise Blocked("watchdog_not_ready")
    generated = datetime.fromisoformat(str(state["generated_at"]).replace("Z", "+00:00"))
    if abs((datetime.now(timezone.utc) - generated).total_seconds()) > 120:
        raise Blocked("watchdog_state_stale")
    if quarantine.STARTUP.exists() or not quarantine.QUARANTINED.is_file():
        raise Blocked("legacy_startup_not_quarantined")
    if hashlib.sha256(quarantine.QUARANTINED.read_bytes()).hexdigest() != quarantine.ENTRY_SHA256:
        raise Blocked("legacy_startup_hash_mismatch")
    task = pickup.task_runtime_readback()
    if task["state"] != 4 or task["enabled"] is not True:
        raise Blocked("watchdog_task_not_running")
    current = gh("api", f"repos/{REPO}/commits/{quarantine.SOURCE_SHA}")
    if current.get("sha") != quarantine.SOURCE_SHA:
        raise Blocked("source_commit_unavailable")
    branch = gh("api", f"repos/{REPO}/git/ref/heads/{REF}", allow_missing=True)
    if branch:
        raise Blocked("pickup_ref_already_exists_no_replay")
    registry = gh("api", f"repos/{REPO}/actions/runners?per_page=100")
    runners = registry.get("runners")
    if not isinstance(runners, list) or registry.get("total_count") != len(runners):
        raise Blocked("runner_registry_incomplete")
    matches = [r for r in runners if r.get("name") == "DESKTOP-RP23OGS-runtime"]
    if len(matches) != 1 or matches[0].get("status") != "online" or matches[0].get("busy") is not False:
        raise Blocked("runner_not_unique_online_idle")
    return {"result": "PREFLIGHT_OK", "host": quarantine.HOST,
            "source_sha": quarantine.SOURCE_SHA, "ref": REF,
            "runner_id": matches[0].get("id"), "runner_status": "online_idle",
            "task_state": 4, "watchdog_ok": True}


def execute() -> dict:
    result = preflight()
    gh("api", "-X", "POST", f"repos/{REPO}/git/refs",
       "-f", f"ref=refs/heads/{REF}", "-f", f"sha={quarantine.SOURCE_SHA}")
    created = gh("api", f"repos/{REPO}/git/ref/heads/{REF}")
    if created.get("object", {}).get("sha") != quarantine.SOURCE_SHA:
        raise Blocked("created_ref_readback_mismatch_no_dispatch")
    exe = shutil.which("gh")
    if not exe:
        raise Blocked("github_cli_missing_after_branch_creation")
    cp = subprocess.run([exe, "workflow", "run", WORKFLOW, "--repo", REPO,
                         "--ref", REF, "-f", "diagnostic=runner-identity",
                         "-f", "lenovo_control_plane_pickup=true"],
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=30, check=False, shell=False)
    if cp.returncode:
        raise Blocked("dispatch_failed_or_unknown_no_retry")
    result["result"] = "DISPATCH_REQUEST_ACCEPTED"
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm", required=True)
    ns = p.parse_args()
    if ns.confirm != CONFIRM:
        print(json.dumps({"result": "BLOCKED", "reason": "confirmation_invalid"}))
        return 3
    try:
        print(json.dumps(preflight() if ns.preflight_only else execute(), sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, Blocked) else "pickup_dependency_error"
        print(json.dumps({"result": "BLOCKED", "reason": reason}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
