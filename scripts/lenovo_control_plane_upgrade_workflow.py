#!/usr/bin/env python3
"""Governed DEV-only wrapper for the DESKTOP-RP23OGS control-plane upgrader."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

EXPECTED_HOST = "DESKTOP-RP23OGS"
EXPECTED_RUNNER = "DESKTOP-RP23OGS-runtime"
EXPECTED_REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
EXPECTED_ACTOR = "ericson-j-santos"
EXPECTED_CONFIRMATION = "UPGRADE-DESKTOP-FREE-CONTROL-PLANE"
EXPECTED_ISSUE = "147"
WORKTREE_ROOT = Path(r"C:\dev\chatgpt-workers")
CORRELATION = re.compile(r"^rp23ogs-control-plane-upgrade-[1-9][0-9]*-[1-9][0-9]*$")


class WorkflowBlocked(RuntimeError):
    pass


def _required(name: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    if not value:
        raise WorkflowBlocked(f"{name.lower()}_missing")
    return value


def _hex(value: str, length: int, reason: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != length or any(ch not in "0123456789abcdef" for ch in normalized):
        raise WorkflowBlocked(reason)
    return normalized


def _sha(name: str) -> str:
    return _hex(_required(name), 40, f"{name.lower()}_invalid")


def _digest(name: str) -> str:
    return _hex(_required(name), 64, f"{name.lower()}_invalid")


def _identity() -> dict[str, Any]:
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": EXPECTED_REPOSITORY,
        "GITHUB_ACTOR": EXPECTED_ACTOR,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_NAME": EXPECTED_RUNNER,
        "DEPLOYMENT_ENV": "DEV",
        "CONFIRMATION": EXPECTED_CONFIRMATION,
        "ISSUE_NUMBER": EXPECTED_ISSUE,
    }
    for name, required in expected.items():
        if _required(name) != required:
            raise WorkflowBlocked(f"{name.lower()}_mismatch")
    if socket.gethostname().upper() != EXPECTED_HOST:
        raise WorkflowBlocked("physical_host_mismatch")
    target_sha = _sha("TARGET_SOURCE_SHA")
    if _sha("GITHUB_SHA") != target_sha or _sha("ANCHOR_SHA") != target_sha:
        raise WorkflowBlocked("target_sha_mismatch")
    correlation_id = _required("CORRELATION_ID")
    if not CORRELATION.fullmatch(correlation_id):
        raise WorkflowBlocked("correlation_id_invalid")
    target_path = Path(_required("TARGET_PATH")).resolve()
    try:
        target_path.relative_to(WORKTREE_ROOT)
    except ValueError as exc:
        raise WorkflowBlocked("target_path_outside_worktree_root") from exc
    workspace = Path(_required("GITHUB_WORKSPACE")).resolve()
    gateway = workspace / "_rules" / "scripts" / "command_gateway.py"
    policy = workspace / "_rules" / "config" / "command-gateway.policy.json"
    upgrader = target_path / "scripts" / "upgrade_desktop_free_control_plane.py"
    if not all(path.is_file() and not path.is_symlink() for path in (gateway, policy, upgrader)):
        raise WorkflowBlocked("governed_files_missing")
    return {
        "target_sha": target_sha,
        "installed_sha": _sha("EXPECTED_INSTALLED_SHA"),
        "watchdog_digest": _digest("EXPECTED_WATCHDOG_SHA256"),
        "uac_digest": _digest("EXPECTED_UAC_SHA256"),
        "launcher_digest": _digest("EXPECTED_LAUNCHER_SHA256"),
        "correlation_id": correlation_id,
        "target_path": target_path,
        "session_id": _required("SESSION_ID"),
        "gateway": gateway,
        "policy": policy,
        "upgrader": upgrader,
    }


def _last_json(text: str, reason: str) -> dict[str, Any]:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    if not lines:
        raise WorkflowBlocked(reason)
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise WorkflowBlocked(reason) from exc
    if not isinstance(payload, dict):
        raise WorkflowBlocked(reason)
    return payload


def _run_gateway(context: dict[str, Any], *, preflight_only: bool) -> dict[str, Any]:
    risk = "1" if preflight_only else "2"
    timeout = "90" if preflight_only else "180"
    upgrader_args = [
        sys.executable, "-B", str(context["upgrader"]),
        "--source-sha", context["target_sha"],
        "--expected-installed-sha", context["installed_sha"],
        "--expected-watchdog-sha256", context["watchdog_digest"],
        "--expected-uac-sha256", context["uac_digest"],
        "--expected-launcher-sha256", context["launcher_digest"],
        "--confirm", EXPECTED_CONFIRMATION,
    ]
    if preflight_only:
        upgrader_args.append("--preflight-only")
    command = [
        sys.executable, "-B", str(context["gateway"]),
        "--policy", str(context["policy"]),
        "--correlation-id", context["correlation_id"] + ("-preflight" if preflight_only else "-apply"),
        "run", "--cwd", str(context["target_path"]),
        "--session-id", context["session_id"],
        "--risk", risk, "--timeout", timeout,
        "--expected-head", context["target_sha"], "--", *upgrader_args,
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True,
        timeout=int(timeout) + 30, check=False, shell=False,
    )
    gateway = _last_json(completed.stdout or completed.stderr, "gateway_receipt_invalid")
    if (completed.returncode != 0 or gateway.get("result") != "ok"
            or gateway.get("gateway_exit_code") != 0
            or gateway.get("command_exit_code") != 0
            or gateway.get("state_changed") is not False):
        raise WorkflowBlocked("command_gateway_blocked")
    return _last_json(str(gateway.get("stdout") or ""), "upgrade_receipt_invalid")


def _validate_preflight(context: dict[str, Any], payload: dict[str, Any]) -> None:
    if (payload.get("result") != "UPGRADE_PREFLIGHT_OK"
            or payload.get("host") != EXPECTED_HOST
            or payload.get("source_sha") != context["target_sha"]
            or payload.get("previous_source_sha") != context["installed_sha"]
            or payload.get("runner_name") != EXPECTED_RUNNER
            or payload.get("mutation_performed") is not False
            or payload.get("github_pickup_proven") is not False
            or not isinstance(payload.get("runner_pids"), list)
            or len(payload["runner_pids"]) != 1):
        raise WorkflowBlocked("upgrade_preflight_contract_invalid")


def preflight() -> None:
    context = _identity()
    payload = _run_gateway(context, preflight_only=True)
    _validate_preflight(context, payload)
    print(json.dumps({"result": "GOVERNED_UPGRADE_PREFLIGHT_OK", "source_sha": context["target_sha"]}, sort_keys=True))


def _write_output(name: str, value: str) -> None:
    if not name or any(ch in value for ch in "\r\n"):
        raise WorkflowBlocked("github_output_invalid")
    with Path(_required("GITHUB_OUTPUT")).open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"{name}={value}\n")


def apply() -> None:
    context = _identity()
    if context["target_sha"] == context["installed_sha"]:
        payload = _run_gateway(context, preflight_only=True)
        _validate_preflight(context, payload)
        result = {
            "contract": "desktop-free-control-plane-governed-upgrade-v1",
            "result": "CONTROL_PLANE_UPGRADE_REPLAY_NOOP",
            "host": EXPECTED_HOST,
            "source_sha": context["target_sha"],
            "previous_source_sha": context["installed_sha"],
            "mutation_performed": False,
            "credentials_created": False,
            "production_touched": False,
            "reboot_performed": False,
        }
    else:
        payload = _run_gateway(context, preflight_only=False)
        if (payload.get("result") != "CONTROL_PLANE_UPGRADED_PICKUP_PENDING"
                or payload.get("host") != EXPECTED_HOST
                or payload.get("source_sha") != context["target_sha"]
                or payload.get("previous_source_sha") != context["installed_sha"]
                or payload.get("runner_name") != EXPECTED_RUNNER
                or payload.get("runner_process_preserved") is not True
                or payload.get("github_pickup_proven") is not False
                or payload.get("credentials_created") is not False
                or payload.get("production_touched") is not False
                or payload.get("reboot_performed") is not False):
            raise WorkflowBlocked("upgrade_apply_contract_invalid")
        result = {
            "contract": "desktop-free-control-plane-governed-upgrade-v1",
            "result": payload["result"],
            "host": EXPECTED_HOST,
            "source_sha": context["target_sha"],
            "previous_source_sha": context["installed_sha"],
            "mutation_performed": True,
            "runner_process_preserved": True,
            "credentials_created": False,
            "production_touched": False,
            "reboot_performed": False,
        }
    data = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _write_output("upgrade_result", result["result"])
    _write_output("upgrade_receipt_b64", base64.b64encode(data).decode("ascii"))
    _write_output("upgrade_receipt_sha256", hashlib.sha256(data).hexdigest())
    print(result["result"])


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action == "preflight":
        preflight()
    elif action == "apply":
        apply()
    else:
        raise SystemExit("usage: lenovo_control_plane_upgrade_workflow.py {preflight|apply}")
