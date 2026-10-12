"""Read one fixed DEV supervisor receipt; no commands, writes, or remote I/O.

This collector is NOT a transport, signature verifier, or recovery capability.
Only invoke it through a validated session / Command Gateway. Its JSON must not
be treated as authenticated host evidence when delivered by an unsigned channel.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import time
from typing import Any

EXPECTED_HOST = "DESKTOP-PDQK954"
INSTALL_ROOT = Path(r"C:\dev\chatgpt-workers\reqsys-orchestrator-24x7-runtime")
CORRELATION_ID = "desktop-crlf-refresh-20261008-2116"
TARGET_SHA = "0426ea5283a511e7e98b8396e65fc6cf6cb1e620"
CONFIRM = "READ-RECORDED-SUPERVISOR-REFRESH"
MAX_BYTES = 16_384
MAX_ENTRIES = 512
MAX_RECEIPTS = 64
REPARSE_POINT = 0x400
FAILURE_NAME = re.compile(r"refresh-runtime\.failed\.[0-9]{1,16}\.json\Z")
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
ERROR_TYPES = frozenset({"ValueError", "RuntimeError", "OSError", "PermissionError",
                         "FileNotFoundError", "TimeoutExpired", "HTTPError", "URLError"})


class ReceiptError(ValueError):
    """Contains a static, non-sensitive reason only."""


def _guard_path(path: Path, *, directory: bool) -> os.stat_result:
    # Check every ancestor too: rejecting only the leaf misses Windows junctions.
    for part in reversed((path, *path.parents)):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE_POINT:
            raise ReceiptError("linked_or_reparse_path")
        if part != path and not stat.S_ISDIR(info.st_mode):
            raise ReceiptError("invalid_ancestor")
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode):
        raise ReceiptError("invalid_file_type")
    if not directory and info.st_nlink != 1:
        raise ReceiptError("hardlinked_receipt")
    return info


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    # Windows path stat and handle fstat may disagree about st_ctime_ns
    # (creation time versus metadata change time). Python >=3.12 provides
    # st_birthtime_ns for the same stable creation timestamp on both.
    # Preserve inode, size and mtime checks to fail closed on replaced files.
    timestamp = (
        getattr(info, "st_birthtime_ns", info.st_ctime_ns)
        if os.name == "nt"
        else info.st_ctime_ns
    )
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, timestamp)


def _invalid_number(_value: str) -> None:
    raise ReceiptError("invalid_json_number")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError("duplicate_json_key")
        result[key] = value
    return result


def _read(path: Path) -> tuple[dict[str, Any], str, tuple[int, int, int, int, int]]:
    before = _guard_path(path, directory=False)
    if before.st_size > MAX_BYTES:
        raise ReceiptError("receipt_too_large")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise ReceiptError("invalid_opened_file")
            if _fingerprint(opened) != _fingerprint(before):
                raise ReceiptError("receipt_changed_during_read")
            raw = stream.read(MAX_BYTES + 1)
            after_handle = os.fstat(stream.fileno())
    except BaseException:
        # fdopen owns/closed the descriptor once construction succeeded.
        raise
    after = _guard_path(path, directory=False)
    if len(raw) > MAX_BYTES:
        raise ReceiptError("receipt_too_large")
    if not (_fingerprint(before) == _fingerprint(after_handle) == _fingerprint(after)):
        raise ReceiptError("receipt_changed_during_read")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                         parse_constant=_invalid_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ReceiptError("invalid_receipt_json") from None
    if not isinstance(obj, dict):
        raise ReceiptError("invalid_receipt_object")
    return obj, hashlib.sha256(raw).hexdigest(), _fingerprint(after)


def _candidates(control: Path) -> list[Path]:
    _guard_path(control, directory=True)
    result: list[Path] = []
    with os.scandir(control) as entries:
        for index, item in enumerate(entries, 1):
            if index > MAX_ENTRIES:
                raise ReceiptError("directory_scan_limit")
            if item.name in {"refresh-runtime.applied.json", "refresh-runtime.request.json"} or FAILURE_NAME.fullmatch(item.name):
                result.append(control / item.name)
                if len(result) > MAX_RECEIPTS:
                    raise ReceiptError("receipt_scan_limit")
    return sorted(result)


def _timestamp(value: Any, now: float) -> float:
    if type(value) not in {int, float} or not 0 < value <= now + 60 or not math.isfinite(value):
        raise ReceiptError("invalid_receipt_timestamp")
    return float(value)


def _project(obj: dict[str, Any], name: str, now: float) -> dict[str, Any]:
    pending = name == "refresh-runtime.request.json"
    schema = obj.get("version" if pending else "schema_version")
    if type(schema) is not int or schema != 1:
        raise ReceiptError("invalid_receipt_schema")
    if obj.get("target_host") != EXPECTED_HOST or obj.get("expected_sha") != TARGET_SHA:
        raise ReceiptError("receipt_identity_mismatch")
    if pending:
        state = "pending"
        stamp = _timestamp(obj.get("requested_at_epoch"), now)
        detail: dict[str, Any] = {}
    elif name == "refresh-runtime.applied.json":
        state = "applied"
        stamp = _timestamp(obj.get("applied_at_epoch"), now)
        if obj.get("source_sha") != TARGET_SHA or obj.get("readback_verified") is not True:
            raise ReceiptError("applied_receipt_not_verified")
        detail = {"recorded_source_sha": TARGET_SHA}
    else:
        state = "failed"
        stamp = _timestamp(obj.get("failed_at_epoch"), now)
        error = obj.get("error")
        error_type = obj.get("error_type")
        if not isinstance(error, str) or not isinstance(error_type, str):
            raise ReceiptError("invalid_error_fields")
        detail = {"error_type": error_type if error_type in ERROR_TYPES else "other",
                  "error_code": ERROR_CODES.get(error, "unclassified_error"),
                  "raw_error_omitted": True}
    return {"receipt_state": state, "receipt_at_epoch": stamp, **detail}


def _collect(root: Path, *, now: float | None = None) -> dict[str, Any]:
    """Filesystem core; root injection exists only for isolated tests, not CLI."""
    now = time.time() if now is None else now
    _guard_path(root, directory=True)
    control = root / "data" / "control"
    paths = _candidates(control)
    fingerprints: dict[Path, tuple[int, int, int, int, int]] = {}
    matched: list[dict[str, Any]] = []
    for path in paths:
        obj, digest, snapshot = _read(path)
        fingerprints[path] = snapshot
        if obj.get("correlation_id") != CORRELATION_ID:
            continue
        matched.append({**_project(obj, path.name, now), "receipt_sha256": digest})
    if paths != _candidates(control):
        raise ReceiptError("receipt_set_changed")
    for path, fingerprint in fingerprints.items():
        if _fingerprint(_guard_path(path, directory=False)) != fingerprint:
            raise ReceiptError("receipt_changed_during_read")
    if not matched:
        raise ReceiptError("matching_receipt_missing")
    if len(matched) != 1:
        raise ReceiptError("ambiguous_receipts")
    return {"schema_version": 1, "result": "SUPERVISOR_RECEIPT_OBSERVED",
            "host": EXPECTED_HOST, "correlation_id": CORRELATION_ID,
            "target_sha": TARGET_SHA, **matched[0], "read_only": True,
            "trust": "local_collection_unattested", "authoritative_success": False,
            "recovery_allowed": False}


def collect_current_host() -> dict[str, Any]:
    if os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold():
        raise ReceiptError("host_not_authorized")
    return _collect(INSTALL_ROOT)


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "receipt_probe_arguments_invalid\n")


def main(argv: list[str] | None = None) -> int:
    parser = _SafeParser(description=__doc__)
    parser.add_argument("--confirm", required=True, choices=[CONFIRM])
    parser.parse_args(argv)
    try:
        result = collect_current_host()
    except (ReceiptError, OSError, ValueError) as failure:
        # Only closed-set categories leave the host; no raw exception messages.
        if isinstance(failure, ReceiptError):
            reason = failure.args[0] if len(failure.args) == 1 else None
            code = reason if reason in {
                "matching_receipt_missing",
                "receipt_identity_mismatch",
                "ambiguous_receipts",
                "host_not_authorized",
            } else "receipt_invalid"
        elif isinstance(failure, FileNotFoundError):
            code = "receipt_file_missing"
        elif isinstance(failure, PermissionError):
            code = "receipt_access_denied"
        else:
            code = "receipt_io_or_format_error"
        result = {"result": "SUPERVISOR_RECEIPT_BLOCKED", "read_only": True,
                  "blocker_code": code,
                  "trust": "local_collection_unattested", "authoritative_success": False,
                  "recovery_allowed": False}
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
