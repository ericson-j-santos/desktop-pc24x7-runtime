"""Bounded, read-only, fixed-contract forensic summary for a DEV Orchestrator.

Never emit file names, raw errors, paths, correlation IDs or receipt payloads.
The caller fixes the host, root and paths, performs session/Gateway checks, and
keeps recovery disallowed regardless of the result.
"""
from __future__ import annotations

from collections import Counter
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable

ORIGINAL_CORRELATION = "desktop-crlf-refresh-20261008-2116"
ORIGINAL_TARGET = "0426ea5283a511e7e98b8396e65fc6cf6cb1e620"
HOST = "DESKTOP-PDQK954"
FAILURE_NAME = re.compile(r"refresh-runtime\.failed\.[0-9]{1,16}\.json\Z")
BACKUP_NAME = re.compile(r"(?:bootstrap-)?[0-9]{9,16}-[0-9a-f]{12}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
ERROR_CODES = {
    "stable bootstrap unavailable": "stable_bootstrap_unavailable",
    "stable bootstrap import failed": "stable_bootstrap_import_failed",
    "stable bootstrap contract invalid": "stable_bootstrap_contract_invalid",
    "stable bootstrap refresh failed": "stable_bootstrap_refresh_failed",
    "source_root origin is not approved": "source_origin_not_approved",
    "expected_sha is not in main history": "target_not_in_main_history",
    "expected_sha is not in origin/main history": "target_not_in_main_history",
    "runtime refresh independent readback mismatch": "runtime_readback_mismatch",
    "runtime version readback unavailable": "runtime_version_unavailable",
    "runtime version source_sha invalid": "runtime_version_invalid",
    "runtime refresh request expired": "refresh_request_expired",
    "runtime refresh request belongs to another host": "refresh_host_mismatch",
}


def classify_failures(
    paths: list[Path], *, now: float,
    read_fn: Callable[[Path], tuple[dict[str, Any], str, tuple[int, int]]],
    guard_fn: Callable[..., os.stat_result],
) -> dict[str, Any]:
    """Classify only known fixed receipt names; no raw value leaves this scope."""
    if len(paths) > 64 or not math.isfinite(now):
        raise ValueError("FAILURE_INVENTORY_LIMIT")
    codes: Counter[str] = Counter()
    identities: Counter[str] = Counter()
    valid = invalid = 0
    for path in paths:
        if not FAILURE_NAME.fullmatch(path.name):
            raise ValueError("FAILURE_FILE_NAME_INVALID")
        try:
            payload, _, fingerprint = read_fn(path)
            if (type(payload.get("schema_version")) is not int or
                payload["schema_version"] != 1 or
                not isinstance(payload.get("error_type"), str) or
                not isinstance(payload.get("error"), str) or
                len(payload["error"]) > 500 or
                not isinstance(payload.get("failed_at_epoch"), (float, int)) or
                isinstance(payload["failed_at_epoch"], bool) or
                not math.isfinite(payload["failed_at_epoch"]) or
                not 0 < payload["failed_at_epoch"] <= now + 60):
                raise ValueError("RECEIPT_SCHEMA_INVALID")
            correlation = payload.get("correlation_id")
            target = payload.get("expected_sha")
            host = payload.get("target_host")
            if (correlation is not None and not isinstance(correlation, str) or
                target is not None and (not isinstance(target, str) or not SHA_RE.fullmatch(target)) or
                host is not None and not isinstance(host, str)):
                raise ValueError("RECEIPT_IDENTITY_INVALID")
            observed = guard_fn(path, directory=False)
            if (observed.st_size, observed.st_mtime_ns) != fingerprint:
                raise ValueError("RECEIPT_CHANGED_DURING_SCAN")
        except (OSError, ValueError):
            invalid += 1
            continue
        valid += 1
        codes[ERROR_CODES.get(payload["error"], "unclassified_error")] += 1
        if correlation == ORIGINAL_CORRELATION and target == ORIGINAL_TARGET and host == HOST:
            identities["original_exact"] += 1
        elif correlation == ORIGINAL_CORRELATION:
            identities["original_partial"] += 1
        elif correlation is None and target == ORIGINAL_TARGET and host == HOST:
            identities["target_without_correlation"] += 1
        elif correlation is None and target is None and host is None:
            identities["legacy_identity_missing"] += 1
        else:
            identities["different_or_unrelated"] += 1
    return {
        "failure_files_scanned": len(paths),
        "failure_files_parsed": valid,
        "failure_files_invalid": invalid,
        "categories": dict(sorted(codes.items())),
        "identity_groups": dict(sorted(identities.items())),
        "original_exact_receipt_found": identities["original_exact"] == 1,
        "classification_complete": invalid == 0 and valid == len(paths),
        "raw_errors_or_receipts_exported": False,
        "recovery_allowed": False,
    }


def inspect_rollback_structure(root: Path, *, guard_fn: Callable[..., os.stat_result]) -> dict[str, Any]:
    """Stat fixed installed files and candidate backups; DO NOT restore anything."""
    bootstrap_dir = root / "bootstrap"
    bootstrap_files = (bootstrap_dir / "runtime_bootstrap_shim.py",
                       bootstrap_dir / "bootstrap-config.json")
    bootstrap_present = []
    for file in bootstrap_files:
        if file.exists() or file.is_symlink():
            guard_fn(file, directory=False)
            bootstrap_present.append(True)
        else:
            bootstrap_present.append(False)
    backup_dir = root / "data" / "runtime-backups"
    snapshots = incomplete = unknown = 0
    has_backup_dir = backup_dir.exists() or backup_dir.is_symlink()
    if has_backup_dir:
        guard_fn(backup_dir, directory=True)
        with os.scandir(backup_dir) as entries:
            for count, entry in enumerate(entries, 1):
                if count > 128:
                    raise ValueError("BACKUP_INVENTORY_LIMIT")
                if not BACKUP_NAME.fullmatch(entry.name):
                    unknown += 1
                    continue
                item = backup_dir / entry.name
                guard_fn(item, directory=True)
                required = (
                    (item / "orchestrator", True),
                    (item / "scripts", True),
                    (item / "orchestrator" / "__init__.py", False),
                    (item / "scripts" / "service_supervisor.py", False),
                )
                complete = True
                for path, directory in required:
                    if not path.exists() and not path.is_symlink():
                        complete = False
                        break
                    guard_fn(path, directory=directory)
                snapshots += int(complete)
                incomplete += int(not complete)
    return {
        "stable_bootstrap_shim_present": bootstrap_present[0],
        "stable_bootstrap_config_present": bootstrap_present[1],
        "backup_directory_present": has_backup_dir,
        "backup_structurally_complete_count": snapshots,
        "backup_incomplete_count": incomplete,
        "backup_unrecognized_entry_count": unknown,
        "rollback_restoration_tested": False,
        "rollback_verified": False,
        "recovery_allowed": False,
    }
