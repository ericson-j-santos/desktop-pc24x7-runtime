"""Prove recovered Orchestrator DEV starts from fixed snapshots in isolation.

The shadow server binds 127.0.0.1 only, uses an ephemeral port and an
ephemeral SQLite copy, and never starts a worker or touches live startup.
No extracted sensitive data or HTTP payloads leave the Desktop.
"""
from __future__ import annotations

import argparse
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

from desktop_orchestrator_isolated_rollback import (
    EXPECTED_INSTALLED_SHA, HOST, REPO, RUNNER, RUNTIME_ROOT,
    _guard, _copy_code, _same_manifest, code_manifest,
)
from desktop_orchestrator_protected_state import (
    CONFIRM as PROTECTED_CONFIRM, SOURCE_CODE_BACKUP, StateError,
    _read_snapshot, dpapi, RUN_RE, ATTEMPT_RE,
)

CONFIRM = "VERIFY-DESKTOP-ORCHESTRATOR-SHADOW-SERVICE-DEV"


def _state_ok(result: dict[str, Any]) -> bool:
    return (result.get("installed_source_sha") == EXPECTED_INSTALLED_SHA and
            result.get("pending_refresh_present") is False and
            result.get("live_state_consistent") is True)


def _request(port: int, path: str) -> dict[str, Any] | None:
    if path not in ("/readyz", "/healthz"):
        raise StateError("SHADOW_PATH_NOT_ALLOWLISTED")
    connection = HTTPConnection("127.0.0.1", port, timeout=1.0)
    try:
        connection.request("GET", path, headers={"Cache-Control": "no-store"})
        response = connection.getresponse()
        raw = response.read(8193)
        if response.status != 200 or len(raw) > 8192:
            return None
        obj = json.loads(raw.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except (OSError, HTTPException, ValueError):
        return None
    finally:
        connection.close()


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _safe_child_env() -> dict[str, str]:
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE",
            "APPDATA", "LOCALAPPDATA", "PYTHONIOENCODING", "VIRTUAL_ENV"}
    return {k: v for k, v in os.environ.items() if k.upper() in keep}


def start_shadow(*, stage: Path, python_executable: str,
                 port: int, timeout_seconds: float = 10,
                 env: dict[str, str] | None = None,
                 request_fn: Callable[[int, str], dict[str, Any] | None] = _request
                 ) -> dict[str, Any]:
    """Launch *only* the restored server CLI, never a worker or live supervisor."""
    if not 1 <= port <= 65535 or timeout_seconds <= 0 or timeout_seconds > 15:
        raise StateError("SHADOW_ARGUMENT_INVALID")
    _guard(stage, directory=True)
    _guard(stage / "orchestrator/__main__.py", directory=False)
    _guard(stage / "data/orchestrator.db", directory=False)
    command = [
        python_executable, "-m", "orchestrator", "serve",
        "--host", "127.0.0.1", "--port", str(port),
        "--db-path", str(stage / "data/orchestrator.db"),
    ]
    process = None
    observed = False
    exited = False
    try:
        try:
            process = subprocess.Popen(
                command, cwd=stage, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=env if env is not None else _safe_child_env(),
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError:
            raise StateError("SHADOW_START_FAILED") from None
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise StateError("SHADOW_EXITED_EARLY")
            ready = request_fn(port, "/readyz")
            health = request_fn(port, "/healthz")
            if ready and ready.get("ready") is True and health and health.get("ok") is True:
                observed = True
                break
            time.sleep(0.2)
        if not observed:
            raise StateError("SHADOW_READINESS_TIMEOUT")
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
                exited = process.poll() is not None
            except subprocess.TimeoutExpired:
                process.kill()  # ONLY our own new shadow subprocess.
                process.wait(timeout=5)
                exited = process.poll() is not None
        if not exited and process is not None:
            raise StateError("SHADOW_PROCESS_NOT_STOPPED")
    return {
        "shadow_ready": observed, "shadow_health": observed,
        "shadow_process_terminated": exited,
        "shadow_bind": "127.0.0.1", "worker_started": False,
        "live_service_restarted": False, "service_rollback_verified": False,
        "recovery_allowed": False,
    }


def run_shadow(*, root: Path, run_id: str, attempt: str,
               before_fn: Callable[[], dict[str, Any]], python_executable: str,
               unprotect_fn: Callable[[bytes], bytes],
               request_fn: Callable[[int, str], dict[str, Any] | None] = _request,
               port_fn: Callable[[], int] = _port) -> dict[str, Any]:
    if not RUN_RE.fullmatch(run_id) or not ATTEMPT_RE.fullmatch(attempt):
        raise StateError("SHADOW_EXECUTION_ID_INVALID")
    if not _state_ok(before_fn()):
        raise StateError("SHADOW_LIVE_PRECONDITION_INVALID")
    backups = root / "data/runtime-backups"
    _guard(backups, directory=True)
    previous_code = backups / SOURCE_CODE_BACKUP
    current_manifest = code_manifest(root)
    if not _same_manifest(current_manifest, code_manifest(previous_code)):
        raise StateError("SHADOW_CODE_SNAPSHOT_MISMATCH")
    encrypted = backups / f"protected-state-{EXPECTED_INSTALLED_SHA[:12]}-{run_id}-{attempt}"
    restored, tables, _ = _read_snapshot(encrypted, decrypt_fn=unprotect_fn)
    if tables < 1 or len(restored["sqlite"]) < 100:
        raise StateError("SHADOW_DATABASE_INVALID")
    with tempfile.TemporaryDirectory(prefix="orchestrator-shadow-", dir=backups) as temp:
        stage = Path(temp)
        _copy_code(previous_code, stage, current_manifest)
        if not _same_manifest(code_manifest(stage), current_manifest):
            raise StateError("SHADOW_CODE_RESTORE_INVALID")
        data = stage / "data"
        data.mkdir()
        (data / "orchestrator.db").write_bytes(restored["sqlite"])
        result = start_shadow(
            stage=stage, python_executable=python_executable,
            port=port_fn(), env=_safe_child_env(), request_fn=request_fn,
        )
    if not _state_ok(before_fn()) or not _same_manifest(code_manifest(root), current_manifest):
        raise StateError("SHADOW_LIVE_POSTCONDITION_INVALID")
    return {
        **result,
        "result": "SHADOW_ORCHESTRATOR_READY_VERIFIED",
        "restored_sqlite_tables": tables,
        "temporary_database_removed": not stage.exists(),
        "runtime_sha": EXPECTED_INSTALLED_SHA,
        "raw_content_uploaded": False,
        "production_touched": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", choices=[CONFIRM], required=True)
    parser.parse_args()
    evidence: dict[str, Any] = {
        "schema": 1, "host": HOST, "repository": REPO,
        "source_sha": os.environ.get("GITHUB_SHA", ""),
        "result": "SHADOW_ORCHESTRATOR_BLOCKED",
        "service_rollback_verified": False, "recovery_allowed": False,
        "raw_content_uploaded": False, "production_touched": False,
    }
    try:
        if (os.name != "nt" or socket.gethostname().casefold() != HOST.casefold() or
            os.environ.get("RUNNER_NAME") != RUNNER or
            os.environ.get("GITHUB_REPOSITORY") != REPO or
            os.environ.get("GITHUB_ACTIONS") != "true"):
            raise StateError("SHADOW_HOST_INVALID")
        from orchestrator_supervisor_readonly_probe import collect
        result = run_shadow(
            root=RUNTIME_ROOT, run_id=os.environ.get("GITHUB_RUN_ID", ""),
            attempt=os.environ.get("GITHUB_RUN_ATTEMPT", ""), before_fn=collect,
            python_executable=sys.executable,
            unprotect_fn=lambda data: dpapi(data, encrypt=False),
        )
        evidence.update(result)
        exit_code = 0
    except (StateError, OSError, ValueError):
        evidence["blocker_code"] = "SHADOW_VALIDATION_UNAVAILABLE"
        exit_code = 2
    print(json.dumps(evidence, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
