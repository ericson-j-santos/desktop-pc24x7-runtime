"""Fixed Desktop DEV code snapshot and isolated restoration test.

No service restarts, command execution, credential reads, configuration reads,
or production changes. The persisted snapshot is NOT permission to deploy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import tempfile
from typing import Any, Callable

HOST = "DESKTOP-PDQK954"
REPO = "ericson-j-santos/desktop-pc24x7-runtime"
RUNNER = "DESKTOP-PDQK954-runtime"
EXPECTED_INSTALLED_SHA = "33f312d0ac4c25d8420d4589fa0e8bc21d943ebd"
RUNTIME_ROOT = Path(r"C:\dev\chatgpt-workers\reqsys-orchestrator-24x7-runtime")
CONFIRM = "VERIFY-DESKTOP-ORCHESTRATOR-ISOLATED-ROLLBACK-DEV"
MANIFEST = "code-snapshot-manifest.json"
CODE_DIRS = ("orchestrator", "scripts")
ALLOWED_SUFFIXES = {".py", ".pyi", ".ps1", ".cmd", ".bat"}
EXCLUDED_DIRS = {"__pycache__"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
MAX_FILES = 3000
MAX_BYTES = 64 * 1024 * 1024
MAX_SINGLE = 8 * 1024 * 1024
RUN_RE = re.compile(r"[1-9][0-9]{1,17}\Z")
ATTEMPT_RE = re.compile(r"[1-9][0-9]{0,3}\Z")


class RollbackError(ValueError):
    """Closed-set operational error, without file names or raw payloads."""


def _guard(path: Path, *, directory: bool) -> os.stat_result:
    for part in reversed((path, *path.parents)):
        try:
            st = part.lstat()
        except OSError:
            raise RollbackError("FIXED_PATH_MISSING") from None
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            raise RollbackError("FIXED_PATH_REDIRECTED")
        if part != path and not stat.S_ISDIR(st.st_mode):
            raise RollbackError("FIXED_PATH_INVALID")
    if directory and not stat.S_ISDIR(st.st_mode):
        raise RollbackError("FIXED_PATH_INVALID")
    if not directory and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
        raise RollbackError("FIXED_PATH_INVALID")
    return st


def _file_digest(path: Path) -> tuple[str, int]:
    before = _guard(path, directory=False)
    if before.st_size > MAX_SINGLE:
        raise RollbackError("CODE_FILE_SIZE_LIMIT")
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while True:
                part = stream.read(1024 * 1024)
                if not part:
                    break
                size += len(part)
                if size > MAX_SINGLE:
                    raise RollbackError("CODE_FILE_SIZE_LIMIT")
                digest.update(part)
    except OSError:
        raise RollbackError("CODE_FILE_READ_FAILED") from None
    after = _guard(path, directory=False)
    if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) != (
        after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size
    ) or size != before.st_size:
        raise RollbackError("CODE_CHANGED_DURING_READ")
    return digest.hexdigest(), size


def code_manifest(root: Path) -> dict[str, Any]:
    """Inspect only known code directories. Never open runtime data/config/secrets."""
    _guard(root, directory=True)
    content: dict[str, dict[str, Any]] = {}
    total = 0
    visited = 0
    for name in CODE_DIRS:
        directory = root / name
        _guard(directory, directory=True)
        stack = [directory]
        while stack:
            parent = stack.pop()
            _guard(parent, directory=True)
            with os.scandir(parent) as it:
                entries = sorted(list(it), key=lambda e: e.name)
            for item in entries:
                visited += 1
                if visited > MAX_FILES * 2:
                    raise RollbackError("CODE_ENTRY_LIMIT")
                entry = Path(item.path)
                if item.name in EXCLUDED_DIRS and item.is_dir(follow_symlinks=False):
                    _guard(entry, directory=True)
                    continue
                info = entry.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise RollbackError("CODE_PATH_REDIRECTED")
                if stat.S_ISDIR(info.st_mode):
                    stack.append(entry)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise RollbackError("CODE_FILE_TYPE_INVALID")
                if entry.suffix.lower() in EXCLUDED_SUFFIXES:
                    continue
                if (entry.suffix.lower() not in ALLOWED_SUFFIXES or
                    any(word in entry.name.lower() for word in ("secret", "credential", ".env", "private_key", "token"))):
                    raise RollbackError("CODE_FILE_NOT_ALLOWLISTED")
                rel = entry.relative_to(root).as_posix()
                sha, length = _file_digest(entry)
                total += length
                content[rel] = {"sha256": sha, "size": length}
                if len(content) > MAX_FILES or total > MAX_BYTES:
                    raise RollbackError("CODE_VOLUME_LIMIT")
    for required in ("orchestrator/__init__.py", "scripts/service_supervisor.py"):
        if required not in content:
            raise RollbackError("CODE_CONTRACT_INCOMPLETE")
    return {"files": dict(sorted(content.items())), "count": len(content), "total_bytes": total}


def _same_manifest(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return a.get("files") == b.get("files") and a.get("count") == b.get("count") and a.get("total_bytes") == b.get("total_bytes")


def _copy_code(source: Path, target: Path, manifest: dict[str, Any]) -> None:
    for name in CODE_DIRS:
        (target / name).mkdir(parents=True, exist_ok=False)
    for relative in manifest["files"]:
        origin = source / relative
        dest = target / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        _guard(origin, directory=False)
        try:
            shutil.copyfile(origin, dest, follow_symlinks=False)
        except OSError:
            raise RollbackError("SNAPSHOT_COPY_FAILED") from None
        sha, length = _file_digest(dest)
        if {"sha256": sha, "size": length} != manifest["files"][relative]:
            raise RollbackError("SNAPSHOT_COPY_MISMATCH")


def validate_isolated_restore(snapshot: Path, manifest: dict[str, Any], *, work_parent: Path) -> bool:
    """Rebuild into a distinct temporary tree; never touch live directories."""
    _guard(work_parent, directory=True)
    with tempfile.TemporaryDirectory(prefix="isolated-restore-", dir=work_parent) as temp:
        restored = Path(temp)
        _copy_code(snapshot, restored, manifest)
        readback = code_manifest(restored)
        if not _same_manifest(manifest, readback):
            raise RollbackError("ISOLATED_RESTORE_MISMATCH")
    return True


def _manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def snapshot_and_test(root: Path, *, run_id: str, attempt: str, expected_installed_sha: str,
                      before_fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    if not RUN_RE.fullmatch(run_id) or not ATTEMPT_RE.fullmatch(attempt):
        raise RollbackError("EXECUTION_IDENTITY_INVALID")
    if expected_installed_sha != EXPECTED_INSTALLED_SHA:
        raise RollbackError("EXPECTED_VERSION_INVALID")
    before = before_fn()
    if (before.get("installed_source_sha") != expected_installed_sha or
        before.get("live_state_consistent") is not True or
        before.get("pending_refresh_present") is not False):
        raise RollbackError("RUNTIME_PRECONDITION_MISMATCH")
    manifest = code_manifest(root)
    backup_parent = root / "data" / "runtime-backups"
    _guard(backup_parent, directory=True)
    name = f"verified-code-{expected_installed_sha[:12]}-{run_id}-{attempt}"
    target = backup_parent / name
    if target.exists() or target.is_symlink():
        _guard(target, directory=True)
        try:
            recorded = json.loads((target / MANIFEST).read_text("utf-8"))
        except (OSError, ValueError):
            raise RollbackError("SNAPSHOT_REPLAY_INVALID") from None
        if not _same_manifest(recorded, manifest) or recorded.get("runtime_sha") != expected_installed_sha:
            raise RollbackError("SNAPSHOT_REPLAY_MISMATCH")
        if not _same_manifest(code_manifest(target), manifest):
            raise RollbackError("SNAPSHOT_REPLAY_CORRUPT")
        replayed = True
    else:
        # Everything is staged under the same filesystem; publication is one directory rename.
        with tempfile.TemporaryDirectory(prefix="code-snapshot-stage-", dir=backup_parent) as temp:
            staged = Path(temp)
            _copy_code(root, staged, manifest)
            if not _same_manifest(code_manifest(staged), manifest):
                raise RollbackError("SNAPSHOT_STAGE_MISMATCH")
            if not _same_manifest(code_manifest(root), manifest):
                raise RollbackError("SOURCE_CHANGED_DURING_SNAPSHOT")
            payload = {**manifest, "runtime_sha": expected_installed_sha, "kind": "isolated_code_backup"}
            (staged / MANIFEST).write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            if target.exists() or target.is_symlink():
                raise RollbackError("SNAPSHOT_TARGET_CONFLICT")
            # Path.rename does not overwrite an existing nonempty folder on Windows.
            try:
                staged.rename(target)
            except OSError:
                raise RollbackError("SNAPSHOT_PUBLICATION_FAILED") from None
        replayed = False
    if not validate_isolated_restore(target, manifest, work_parent=backup_parent):
        raise RollbackError("ISOLATED_RESTORE_FAILED")
    after = before_fn()
    if (after.get("installed_source_sha") != expected_installed_sha or
        after.get("live_state_consistent") is not True or
        after.get("pending_refresh_present") is not False or
        not _same_manifest(code_manifest(root), manifest)):
        raise RollbackError("SOURCE_CHANGED_DURING_VALIDATION")
    return {
        "backup_kind": "code_only_not_full_runtime",
        "backup_sha256": _manifest_digest(manifest),
        "snapshot_file_count": manifest["count"],
        "snapshot_size_bytes": manifest["total_bytes"],
        "local_snapshot_present": True,
        "replayed": replayed,
        "isolated_restore_verified": True,
        "configs_or_secrets_read": False,
        "live_processes_modified": False,
        "current_service_rollback_verified": False,
        "recovery_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True, choices=[CONFIRM])
    args = parser.parse_args()
    output: dict[str, Any] = {
        "schema_version": 1, "result": "ISOLATED_ROLLBACK_BLOCKED", "host": HOST,
        "source_sha": os.getenv("GITHUB_SHA", ""),
        "read_only_to_service": True, "recovery_allowed": False,
        "secrets_read": False, "production_touched": False,
    }
    try:
        if (os.name != "nt" or socket.gethostname().casefold() != HOST.casefold()
            or os.getenv("GITHUB_REPOSITORY") != REPO
            or os.getenv("RUNNER_NAME") != RUNNER
            or os.getenv("GITHUB_ACTIONS") != "true"):
            raise RollbackError("HOST_OR_EXECUTOR_INVALID")
        from orchestrator_supervisor_readonly_probe import collect
        verified = snapshot_and_test(
            RUNTIME_ROOT,
            run_id=os.getenv("GITHUB_RUN_ID", ""), attempt=os.getenv("GITHUB_RUN_ATTEMPT", ""),
            expected_installed_sha=EXPECTED_INSTALLED_SHA,
            before_fn=collect,
        )
        output.update(verified)
        output["result"] = "ISOLATED_ROLLBACK_VERIFIED"
        code = 0
    except (RollbackError, OSError, ValueError) as exc:
        output["blocker_code"] = str(exc) if isinstance(exc, RollbackError) else "ISOLATED_OPERATION_FAILED"
        code = 2
    print(json.dumps(output, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
