#!/usr/bin/env python3
"""Terminate only the protected duplicate desktop-runtime runner listener."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import importlib.util
import json
import os
from pathlib import Path
import time


CONFIRM = "TERMINATE-DUPLICATE-DESKTOP-RUNTIME-LISTENER"
EXPECTED_RUNNER = "DESKTOP-PDQK954-runtime"


class ConflictResolutionError(RuntimeError):
    pass


def load_watchdog():
    path = Path(__file__).with_name("desktop_control_plane_watchdog.py")
    spec = importlib.util.spec_from_file_location("runner_watchdog_conflict", path)
    if spec is None or spec.loader is None:
        raise ConflictResolutionError("watchdog_import_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def validate_and_select_pid(
    watchdog, local: Path, expected_pid: int | None = None
) -> int:
    target_home = local / "DesktopPC24x7" / "GitHubRunner"
    legacy_home = local / "ReqSys" / "Pc24x7GitHubRunner"
    target_config = json.loads((target_home / ".runner").read_text(encoding="utf-8-sig"))
    if target_config.get("agentName") != EXPECTED_RUNNER:
        raise ConflictResolutionError("target_runner_identity_mismatch")

    logs = [item for item in (target_home / "_diag").glob("Runner_*.log") if item.is_file()]
    if not logs:
        raise ConflictResolutionError("target_runner_log_missing")
    latest = max(logs, key=lambda item: item.stat().st_mtime_ns)
    if time.time() - latest.stat().st_mtime > 600:
        raise ConflictResolutionError("target_runner_conflict_log_stale")
    text = latest.read_text(encoding="utf-8", errors="replace")[-200000:]
    if "TaskAgentSessionConflictException" not in text or "A session for this runner already exists." not in text:
        raise ConflictResolutionError("target_runner_session_conflict_not_proven")

    target_expected = normalized(target_home / "bin" / "Runner.Listener.exe")
    legacy_prefix = normalized(legacy_home) + os.sep
    target_pids: list[int] = []
    legacy_pids: list[int] = []
    unresolved: list[int] = []
    unexpected: list[int] = []
    runner_pids = watchdog._runner_process_ids()
    observed_paths: dict[int, str | None] = {}
    for pid in runner_pids:
        path = watchdog._process_executable_path(pid)
        if path is None:
            observed_paths[pid] = None
            unresolved.append(pid)
            continue
        observed = normalized(path)
        observed_paths[pid] = observed
        if observed == target_expected:
            target_pids.append(pid)
        elif observed.startswith(legacy_prefix):
            legacy_pids.append(pid)
        else:
            unexpected.append(pid)

    if expected_pid is not None:
        if expected_pid <= 0 or expected_pid not in runner_pids:
            raise ConflictResolutionError("expected_protected_listener_missing")
        expected_path = observed_paths[expected_pid]
        if expected_path is not None and expected_path != target_expected:
            raise ConflictResolutionError("expected_listener_identity_mismatch")
        other_target_pids = [pid for pid in target_pids if pid != expected_pid]
        unresolved_other = [pid for pid in unresolved if pid != expected_pid]
        accounted = {expected_pid, *other_target_pids, *legacy_pids}
        if len(other_target_pids) != 1:
            raise ConflictResolutionError("surviving_target_listener_not_unique")
        if len(legacy_pids) != 1:
            raise ConflictResolutionError("legacy_listener_not_unique")
        if unresolved_other:
            raise ConflictResolutionError("additional_protected_listener_present")
        if unexpected or accounted != set(runner_pids):
            raise ConflictResolutionError("unexpected_listener_present")
        return expected_pid

    if len(target_pids) != 1:
        raise ConflictResolutionError("target_listener_not_unique")
    if len(legacy_pids) != 1:
        raise ConflictResolutionError("legacy_listener_not_unique")
    if len(unresolved) != 1:
        raise ConflictResolutionError("protected_duplicate_not_unique")
    if unexpected:
        raise ConflictResolutionError("unexpected_listener_present")
    return unresolved[0]


def validated_evidence_path(local: Path, raw: str, expected_pid: int) -> Path:
    path = Path(raw)
    expected_parent = local / "DesktopPC24x7" / "ConflictResolution"
    if normalized(path.parent) != normalized(expected_parent):
        raise ConflictResolutionError("evidence_path_not_allowed")
    if path.name != f"result-{expected_pid}.json":
        raise ConflictResolutionError("evidence_filename_not_allowed")
    return path


def emit(payload: dict[str, object], evidence_path: Path | None = None) -> None:
    encoded = json.dumps(payload, sort_keys=True)
    if evidence_path is not None:
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = evidence_path.with_suffix(".tmp")
        temporary.write_text(encoded + "\n", encoding="utf-8")
        os.replace(temporary, evidence_path)
    print(encoded)


def terminate(pid: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    terminate_process = kernel32.TerminateProcess
    terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
    terminate_process.restype = wintypes.BOOL
    wait_for_single = kernel32.WaitForSingleObject
    wait_for_single.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait_for_single.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = open_process(0x0001 | 0x00100000, False, pid)  # TERMINATE | SYNCHRONIZE
    if not handle:
        raise ConflictResolutionError(
            f"protected_listener_open_failed:winerror={ctypes.get_last_error()}"
        )
    try:
        if not terminate_process(handle, 1):
            raise ConflictResolutionError(
                f"protected_listener_terminate_failed:winerror={ctypes.get_last_error()}"
            )
        result = wait_for_single(handle, 10000)
        if result != 0:
            raise ConflictResolutionError(f"protected_listener_exit_timeout:wait={result}")
    finally:
        close_handle(handle)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--expected-pid", type=int)
    parser.add_argument("--evidence-file")
    args = parser.parse_args()
    if args.confirm != CONFIRM:
        emit({"ok": False, "error": "confirmation_invalid"})
        return 2
    local_raw = os.environ.get("LOCALAPPDATA")
    if not local_raw:
        emit({"ok": False, "error": "localappdata_unavailable"})
        return 2
    local = Path(local_raw)
    evidence_path: Path | None = None
    if args.evidence_file:
        if args.expected_pid is None:
            emit({"ok": False, "error": "evidence_requires_expected_pid"})
            return 2
        try:
            evidence_path = validated_evidence_path(
                local, args.evidence_file, args.expected_pid
            )
        except (ConflictResolutionError, OSError, ValueError) as exc:
            emit({"ok": False, "error": str(exc)})
            return 2
    watchdog = load_watchdog()
    try:
        pid = validate_and_select_pid(watchdog, local, args.expected_pid)
        terminate(pid)
        remaining = watchdog._runner_process_ids()
        if pid in remaining:
            raise ConflictResolutionError("protected_listener_still_present")
    except (ConflictResolutionError, OSError, ValueError) as exc:
        emit(
            {
                "ok": False,
                "error": str(exc),
                "production_touched": False,
                "legacy_runner_preserved": True,
            },
            evidence_path,
        )
        return 3
    emit(
        {
            "ok": True,
            "result": "duplicate_listener_terminated",
            "terminated_pid": pid,
            "production_touched": False,
            "legacy_runner_preserved": True,
        },
        evidence_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
