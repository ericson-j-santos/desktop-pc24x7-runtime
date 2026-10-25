"""Read-only forensic inventory of ONE failed Qwen issue-8 Windows sandbox.

Runs exclusively after a validated Session Launcher and Command Gateway session.
Never invokes Ollama, Git, deletion, writes, token access or process termination.
The failed-run identity and original worktree are immutable code constants.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

RUN_ID = 40214413825
RUN_SHA = "50d35e3126d68872c9b3c9d7edde34878d39508e"
RULES_SHA = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"
ROOT = Path("C:/dev/chatgpt-workers")
WORKTREE = "wt-chat-issue8-qwen-fenc-desktop-pdqk-20261025-170210-9b48"
PREFIX = "issue8-qwen-"
MAX_ENTRIES = 4096
MAX_DEPTH = 18
MAX_BUNDLE_BYTES = 96000
WIN_READONLY = getattr(stat, "FILE_ATTRIBUTE_READONLY", 1)
SHA40 = re.compile(r"[0-9a-f]{40}\Z")


class ProbeBlocked(RuntimeError):
    """Only fixed codes are allowed in the public result."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ProbeBlocked(code)


def _not_link(path: Path) -> bool:
    try:
        return not path.is_symlink() and not getattr(path, "is_junction", lambda: False)()
    except (OSError, ValueError):
        return False


def confined_existing_worktree(workers: Path) -> Path:
    """No caller-chosen roots, path traversal, or symlink/junction escapes."""
    require(workers.is_absolute() and workers.is_dir() and _not_link(workers),
            "probe_root_not_verified")
    target = workers / WORKTREE
    require(target.parent == workers and _not_link(target) and target.is_dir(),
            "probe_failed_worktree_unavailable")
    require(target.resolve() == workers.resolve() / WORKTREE,
            "probe_failed_worktree_outside_root")
    return target


def win_exclusive_metadata_probe(path: Path, directory: bool) -> int:
    """Ask Windows for a short-lived exclusive metadata handle, never write.

    0 means no current contention; 5 access denied, 32 sharing violation.
    A snapshot cannot prove which handle blocked a historical deletion.
    """
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    flags = 0x02000000 if directory else 0  # FILE_FLAG_BACKUP_SEMANTICS
    handle = create(str(path), 0, 0, None, 3, flags, None)  # OPEN_EXISTING
    bad = ctypes.c_void_p(-1).value
    if handle == bad:
        error = ctypes.get_last_error()
        return error if error in (2, 3, 5, 32, 33) else 999
    require(bool(close(handle)), "probe_metadata_handle_close_failed")
    return 0


def _classify(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in (".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3"):
        return "sqlite"
    if suffix in (".pack", ".idx", ".rev", ".lock"):
        return "git_or_lock"
    if suffix in (".pyc", ".pyo"):
        return "bytecode"
    if suffix in (".json", ".patch", ".bundle"):
        return "artifact"
    return "other"


def inventory_sandbox(sandbox: Path, *, check=None,
                      max_entries: int = MAX_ENTRIES) -> dict:
    require(sandbox.is_dir() and _not_link(sandbox)
            and sandbox.name.startswith(PREFIX)
            and max_entries > 0, "probe_sandbox_scope_invalid")
    checker = check or win_exclusive_metadata_probe
    result = {
        "file_count": 0, "directory_count": 1,
        "readonly_count": 0, "category_counts": {},
        "sharing_violation_count": 0, "access_denied_count": 0,
        "other_open_failure_count": 0,
        "bundle_found": False, "bundle_bytes": 0, "bundle_sha256": None,
        "model_receipt_count": 0, "sqlite_file_count": 0,
        "readable_sandbox": True, "historical_lock_identity_proved": False,
    }
    stack = [(sandbox, 0)]
    seen = 0
    while stack:
        folder, depth = stack.pop()
        require(depth <= MAX_DEPTH and _not_link(folder),
                "probe_directory_boundary_invalid")
        try:
            items = sorted(folder.iterdir(), key=lambda x: x.name.casefold())
        except OSError:
            raise ProbeBlocked("probe_directory_unreadable") from None
        for path in items:
            seen += 1
            require(seen <= max_entries and _not_link(path),
                    "probe_inventory_limit_or_link")
            try:
                meta = path.stat(follow_symlinks=False)
            except OSError:
                raise ProbeBlocked("probe_metadata_unreadable") from None
            is_dir = stat.S_ISDIR(meta.st_mode)
            require(is_dir or stat.S_ISREG(meta.st_mode),
                    "probe_special_file_rejected")
            if is_dir:
                result["directory_count"] += 1
                stack.append((path, depth + 1))
            else:
                result["file_count"] += 1
                kind = _classify(path)
                result["category_counts"][kind] = (
                    result["category_counts"].get(kind, 0) + 1
                )
                if kind == "sqlite":
                    result["sqlite_file_count"] += 1
                # A receipt is only a file-presence signal, not attested success.
                if path.parent.name == "repair-state" and path.suffix == ".json":
                    result["model_receipt_count"] += 1
                if path == sandbox / "change.bundle":
                    require(not result["bundle_found"] and
                            200 < meta.st_size <= MAX_BUNDLE_BYTES,
                            "probe_bundle_size_invalid")
                    raw = path.read_bytes()  # Known public Git bundle only.
                    require(len(raw) == meta.st_size, "probe_bundle_read_changed")
                    result["bundle_found"] = True
                    result["bundle_bytes"] = len(raw)
                    result["bundle_sha256"] = hashlib.sha256(raw).hexdigest()
            if getattr(meta, "st_file_attributes", 0) & WIN_READONLY:
                result["readonly_count"] += 1
            code = checker(path, is_dir)
            if code in (32, 33):
                result["sharing_violation_count"] += 1
            elif code == 5:
                result["access_denied_count"] += 1
            elif code != 0:
                result["other_open_failure_count"] += 1
    return result


def execute() -> dict:
    e = os.environ
    require(os.name == "nt" and e.get("COMPUTERNAME", "").upper() == "DESKTOP-PDQK954"
            and e.get("RUNNER_NAME") == "DESKTOP-PDQK954-runtime"
            and e.get("GITHUB_ACTIONS") == "true"
            and e.get("GITHUB_REPOSITORY") == "ericson-j-santos/desktop-pc24x7-runtime"
            and e.get("EXPECTED_RUNTIME_SHA", "") != RUN_SHA
            and SHA40.fullmatch(e.get("EXPECTED_RUNTIME_SHA", "")) is not None
            and e.get("RULES_SHA") == RULES_SHA
            and e.get("SESSION_LAUNCH_RESULT") == "SESSION_LAUNCH_OK"
            and e.get("SESSION_STATE_VALIDATED") == "true",
            "probe_physical_admission_invalid")
    target = Path(e.get("SESSION_TARGET_PATH") or "/missing")
    require(target.is_absolute() and target.resolve() == Path.cwd().resolve()
            and target != ROOT / WORKTREE,
            "probe_session_not_isolated")
    original = confined_existing_worktree(ROOT)
    sandboxes = sorted(
        (p for p in original.iterdir() if p.name.startswith(PREFIX)),
        key=lambda x: x.name.casefold(),
    )
    require(len(sandboxes) == 1, "probe_missing_or_ambiguous_sandbox")
    observation = inventory_sandbox(sandboxes[0])
    require(observation["file_count"] > 0,
            "probe_no_residual_files")
    return {
        "result": "ISSUE8_READ_ONLY_RESIDUAL_INVENTORY",
        "physical_run_id": RUN_ID, "physical_sha": RUN_SHA,
        "correlation_id": "qwen8-fenced-40214413825-1",
        "no_model_inference": True, "no_files_mutated": True,
        "no_cas_written": True, "ready_for_pr": False,
        **observation,
    }


def main() -> int:
    sys.dont_write_bytecode = True
    try:
        print(json.dumps(execute(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, ProbeBlocked) and re.fullmatch(
            r"[a-z][a-z0-9_]{2,80}", str(exc)) else "probe_unverified"
        print(json.dumps({
            "result": "ISSUE8_READ_ONLY_PROBE_BLOCKED",
            "reason_code": code, "no_cas_written": True,
            "ready_for_pr": False, "no_model_inference": True,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
