#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPECTED_HOST = "DESKTOP-PDQK954"
SCRIPT_PATH = Path(
    r"C:\dev\chatgpt-workers\reqsys-orchestrator-24x7-runtime\scripts\Activate-Desktop-Stable-Bootstrap.ps1"
)
EXPECTED_SHA256 = "377188bd48bacdd588c59510d50be16cd6bb7c32f21d7fc55a1f24e9a566d5bb"
CONFIRM = "EXECUTE-CONFIRMED-DESKTOP-STABLE-BOOTSTRAP"


class ExecutorError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize(value: Any, limit: int = 500) -> str:
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    return text[:limit]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_evidence_path(path: Path) -> Path:
    root = Path.cwd().resolve()
    target = path.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ExecutorError("evidence_path_outside_workspace") from exc
    return target


def execute(*, confirm: str, evidence_file: Path) -> dict[str, Any]:
    if confirm != CONFIRM:
        raise ExecutorError("confirmation_invalid")
    host = socket.gethostname()
    if host.casefold() != EXPECTED_HOST.casefold():
        raise ExecutorError(f"unexpected_host:{host}")
    if os.name != "nt":
        raise ExecutorError("windows_required")
    if not SCRIPT_PATH.is_file():
        raise ExecutorError("bootstrap_script_missing")

    observed_sha = file_sha256(SCRIPT_PATH)
    if observed_sha != EXPECTED_SHA256:
        raise ExecutorError("bootstrap_script_sha256_mismatch")

    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    powershell = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file():
        raise ExecutorError("windows_powershell_missing")

    completed = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT_PATH),
        ],
        cwd=str(SCRIPT_PATH.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
        shell=False,
    )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    success_marker = "REQSYS_DESKTOP_BOOTSTRAP_OK" in stdout
    failure_marker = "REQSYS_DESKTOP_BOOTSTRAP_FALHOU" in stdout
    ok = completed.returncode == 0 and success_marker

    evidence = {
        "schema_version": "1",
        "generated_at_utc": now_iso(),
        "ok": ok,
        "result": (
            "DESKTOP_STABLE_BOOTSTRAP_EXECUTED"
            if ok
            else "DESKTOP_STABLE_BOOTSTRAP_BLOCKED"
        ),
        "host": EXPECTED_HOST,
        "script_path": str(SCRIPT_PATH),
        "script_sha256": observed_sha,
        "expected_sha256": EXPECTED_SHA256,
        "exit_code": int(completed.returncode),
        "success_marker": success_marker,
        "failure_marker": failure_marker,
        "stdout_tail": sanitize("\n".join(stdout.splitlines()[-12:])),
        "stderr_tail": sanitize("\n".join(stderr.splitlines()[-12:])),
        "production_touched": False,
        "secrets_read": False,
        "reboot_performed": False,
        "admin_required": False,
    }
    target = validate_evidence_path(evidence_file)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(evidence, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = execute(confirm=args.confirm, evidence_file=args.evidence_file)
    except (ExecutorError, OSError, subprocess.SubprocessError) as exc:
        evidence = {
            "schema_version": "1",
            "generated_at_utc": now_iso(),
            "ok": False,
            "result": "DESKTOP_STABLE_BOOTSTRAP_BLOCKED",
            "host": EXPECTED_HOST,
            "reason": sanitize(exc),
            "production_touched": False,
            "secrets_read": False,
            "reboot_performed": False,
            "admin_required": False,
        }
        try:
            target = validate_evidence_path(args.evidence_file)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(evidence, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass
        print(json.dumps(evidence, sort_keys=True))
        return 2

    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
