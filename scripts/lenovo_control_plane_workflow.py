#!/usr/bin/env python3
"""Fixed GitHub Actions orchestration for the Lenovo control-plane pickup."""
from __future__ import annotations

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
EXPECTED_EVIDENCE_REL = r"artifacts\lenovo-control-plane-pickup\evidence.json"
CORRELATION = re.compile(r"^lenovo-control-plane-pickup-[1-9][0-9]*-[1-9][0-9]*$")
SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


class WorkflowBlocked(RuntimeError):
    pass


def _required_env(name: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    if not value:
        raise WorkflowBlocked(f"{name.lower()}_missing")
    return value


def _require_sha(value: str, reason: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 40 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise WorkflowBlocked(reason)
    return normalized


def _admit_identity() -> tuple[Path, str, str]:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise WorkflowBlocked("github_actions_required")
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise WorkflowBlocked("workflow_dispatch_required")
    if os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise WorkflowBlocked("repository_mismatch")
    if os.environ.get("RUNNER_NAME") != EXPECTED_RUNNER:
        raise WorkflowBlocked("runner_name_mismatch")
    if socket.gethostname().upper() != EXPECTED_HOST:
        raise WorkflowBlocked("physical_host_mismatch")
    workspace = Path(_required_env("GITHUB_WORKSPACE")).resolve()
    sha = _require_sha(_required_env("GITHUB_SHA"), "github_sha_invalid")
    correlation_id = _required_env("CORRELATION_ID")
    if not CORRELATION.fullmatch(correlation_id):
        raise WorkflowBlocked("correlation_id_invalid")
    return workspace, sha, correlation_id


def _last_json(stdout: str) -> dict[str, Any]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise WorkflowBlocked("session_launcher_output_missing")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise WorkflowBlocked("session_launcher_output_invalid") from exc
    if not isinstance(payload, dict):
        raise WorkflowBlocked("session_launcher_output_invalid")
    return payload


def _write_output(name: str, value: str) -> None:
    if not name or any(ch in value for ch in "\r\n"):
        raise WorkflowBlocked("github_output_value_invalid")
    output = Path(_required_env("GITHUB_OUTPUT"))
    with output.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"{name}={value}\n")


def bootstrap() -> None:
    workspace, anchor_sha, correlation_id = _admit_identity()
    ref_name = _required_env("GITHUB_REF_NAME")
    if (
        not SAFE_REF.fullmatch(ref_name)
        or ".." in ref_name
        or ref_name.endswith("/")
    ):
        raise WorkflowBlocked("github_ref_name_invalid")
    launcher = workspace / "_rules" / "scripts" / "session_launcher.py"
    policy = workspace / "_rules" / "config" / "command-gateway.policy.json"
    if not launcher.is_file() or not policy.is_file():
        raise WorkflowBlocked("canonical_bootstrap_files_missing")
    command = [
        sys.executable,
        str(launcher),
        "--policy",
        str(policy),
        "--repo",
        str(workspace),
        "--session-prefix",
        "lenovo-control-plane-pickup",
        "--correlation-id",
        correlation_id,
        "--expected-head",
        anchor_sha,
        "--sync-ref",
        f"origin/{ref_name}",
        "--require-runner-version-preflight",
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise WorkflowBlocked(f"session_launcher_exit_{completed.returncode}")
    payload = _last_json(completed.stdout)
    preflight = payload.get("runner_version_preflight")
    if (
        payload.get("result") != "SESSION_LAUNCH_OK"
        or payload.get("state_validated") is not True
        or payload.get("head") != anchor_sha
        or not isinstance(preflight, dict)
        or preflight.get("ok") is not True
    ):
        raise WorkflowBlocked("lenovo_session_launch_blocked")
    target_path = str(payload.get("target_path") or "").strip()
    session_id = str(payload.get("session_id") or "").strip()
    if not target_path or not session_id or any(ch in session_id for ch in "\r\n"):
        raise WorkflowBlocked("session_identity_invalid")
    _write_output("target_path", target_path)
    _write_output("session_id", session_id)
    _write_output("anchor_sha", anchor_sha)
    print(
        json.dumps(
            {
                "result": "LENOVO_SESSION_BOOTSTRAP_OK",
                "head": anchor_sha,
                "runner_name": EXPECTED_RUNNER,
                "state_validated": True,
            },
            sort_keys=True,
        )
    )


def prove() -> None:
    workspace, github_sha, correlation_id = _admit_identity()
    anchor_sha = _require_sha(_required_env("ANCHOR_SHA"), "anchor_sha_invalid")
    if anchor_sha != github_sha:
        raise WorkflowBlocked("anchor_sha_mismatch")
    target_path = Path(_required_env("TARGET_PATH")).resolve()
    session_id = _required_env("SESSION_ID")
    evidence_rel = _required_env("EVIDENCE_REL")
    if evidence_rel != EXPECTED_EVIDENCE_REL:
        raise WorkflowBlocked("evidence_path_mismatch")
    gateway = workspace / "_rules" / "scripts" / "command_gateway.py"
    policy = workspace / "_rules" / "config" / "command-gateway.policy.json"
    probe = target_path / "scripts" / "lenovo_control_plane_pickup.py"
    if not gateway.is_file() or not policy.is_file() or not probe.is_file():
        raise WorkflowBlocked("governed_probe_files_missing")
    command = [
        sys.executable,
        str(gateway),
        "--policy",
        str(policy),
        "--correlation-id",
        correlation_id,
        "run",
        "--cwd",
        str(target_path),
        "--session-id",
        session_id,
        "--risk",
        "1",
        "--timeout",
        "60",
        "--expected-head",
        anchor_sha,
        "--",
        "python",
        "-B",
        str(probe),
        "--expected-source-sha",
        github_sha,
        "--evidence-file",
        evidence_rel,
    ]
    completed = subprocess.run(command, timeout=90, check=False, shell=False)
    if completed.returncode != 0:
        raise WorkflowBlocked(f"command_gateway_exit_{completed.returncode}")
