"""Read only fixed Orchestrator DEV supervisor files and localhost worker identity.

This probe has no free-form path/host/command arguments and cannot recover a host.
GitHub Actions artifacts are not cryptographic attestation of the physical host.
"""
from __future__ import annotations

import argparse
from http.client import HTTPConnection, HTTPException
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import time
from typing import Any, Callable

from orchestrator_supervisor_failure_inventory import classify_failures, inspect_rollback_structure

EXPECTED_HOST = "DESKTOP-PDQK954"
INSTALL_ROOT = Path(r"C:\dev\chatgpt-workers\reqsys-orchestrator-24x7-runtime")

REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
RUNNER = "DESKTOP-PDQK954-runtime"
CONFIRM = "READ-DESKTOP-ORCHESTRATOR-RUNTIME-DEV"
WORKER = "desktop-pdqk954"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
CID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")


class ProbeError(ValueError):
    pass


def _guard_path(path: Path, *, directory: bool) -> os.stat_result:
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except OSError:
            raise ProbeError("FIXED_PATH_MISSING") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ProbeError("FIXED_PATH_REDIRECTED")
        if part != path and not stat.S_ISDIR(info.st_mode):
            raise ProbeError("FIXED_PATH_INVALID")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ProbeError("FIXED_PATH_INVALID")
    if not directory and info.st_nlink != 1:
        raise ProbeError("FIXED_PATH_LINKED")
    return info


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError("FIXED_JSON_INVALID")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ProbeError("FIXED_JSON_INVALID")


def _read(path: Path) -> tuple[dict[str, Any], str, tuple[int, int]]:
    before = _guard_path(path, directory=False)
    if before.st_size > 16384:
        raise ProbeError("FIXED_FILE_OVERSIZE")
    with path.open("rb") as stream:
        raw = stream.read(16385)
    after = _guard_path(path, directory=False)
    if len(raw) > 16384 or (before.st_ino, before.st_mtime_ns, before.st_size) != (after.st_ino, after.st_mtime_ns, after.st_size):
        raise ProbeError("FIXED_FILE_RACE_OR_OVERSIZE")
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ProbeError("FIXED_JSON_INVALID") from None
    if not isinstance(data, dict):
        raise ProbeError("FIXED_JSON_INVALID")
    return data, hashlib.sha256(raw).hexdigest(), (after.st_size, after.st_mtime_ns)


def _candidates(control: Path) -> list[Path]:
    _guard_path(control, directory=True)
    paths = []
    with os.scandir(control) as entries:
        for count, item in enumerate(entries, 1):
            if count > 512:
                raise ProbeError("CONTROL_SCAN_LIMIT")
            if item.name in {"refresh-runtime.request.json", "refresh-runtime.applied.json"} or re.fullmatch(r"refresh-runtime\.failed\.[0-9]{1,16}\.json", item.name):
                paths.append(control / item.name)
                if len(paths) > 66:
                    raise ProbeError("CONTROL_SCAN_LIMIT")
    return sorted(paths)


def live_worker() -> dict[str, Any]:
    connection = HTTPConnection("127.0.0.1", 8787, timeout=4)
    try:
        connection.request("GET", "/v1/workers", headers={"Cache-Control": "no-store"})
        response = connection.getresponse()
        raw = response.read(262145)
        if response.status != 200 or len(raw) > 262144:
            raise ProbeError("WORKER_HTTP_INVALID")
        root = json.loads(raw.decode("utf-8"))
    except (OSError, HTTPException, UnicodeError, ValueError):
        raise ProbeError("WORKER_HTTP_UNAVAILABLE") from None
    finally:
        connection.close()
    workers = root.get("workers") if isinstance(root, dict) else None
    if not isinstance(workers, list):
        raise ProbeError("WORKER_PAYLOAD_INVALID")
    matching = [w for w in workers if isinstance(w, dict)
                and str(w.get("worker_id", "")).casefold() == WORKER
                and str(w.get("device_name", "")).casefold() == EXPECTED_HOST.casefold()]
    if len(matching) != 1 or not isinstance(matching[0].get("capabilities"), dict):
        raise ProbeError("WORKER_IDENTITY_MISSING")
    w = matching[0]
    caps = w["capabilities"]
    source_sha = caps.get("runtime_source_sha")
    instance = caps.get("worker_instance_id")
    if not isinstance(source_sha, str) or not SHA_RE.fullmatch(source_sha):
        raise ProbeError("WORKER_SHA_INVALID")
    if not isinstance(instance, str) or not re.fullmatch(r"[0-9a-f]{32}", instance):
        raise ProbeError("WORKER_INSTANCE_INVALID")
    return {"runtime_source_sha": source_sha, "instance_present": True,
            "fresh": w.get("fresh") is True, "eligible": w.get("eligible") is True,
            "online": w.get("controller_online") is True, "auth_valid": w.get("auth_valid") is True}


def collect(*, root: Path = INSTALL_ROOT, now: float | None = None,
            worker_fn: Callable[[], dict[str, Any]] = live_worker) -> dict[str, Any]:
    now = time.time() if now is None else now
    _guard_path(root, directory=True)
    version, version_digest, _ = _read(root / "runtime-version.json")
    if version.get("schema_version") != 1 or not isinstance(version.get("source_sha"), str) or not SHA_RE.fullmatch(version["source_sha"]):
        raise ProbeError("VERSION_METADATA_INVALID")
    status, _, _ = _read(root / "runtime-status.json")
    stamp = status.get("updated_at_epoch")
    if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp <= 0 or stamp > now + 60:
        raise ProbeError("SUPERVISOR_STATUS_INVALID")
    control = root / "data" / "control"
    candidates = _candidates(control)
    for path in candidates:
        _guard_path(path, directory=False)
    if candidates != _candidates(control):
        raise ProbeError("CONTROL_DIRECTORY_CHANGED")
    names = [p.name for p in candidates]
    failure_inventory = classify_failures(
        [p for p in candidates if p.name.startswith("refresh-runtime.failed.")],
        now=now, read_fn=_read, guard_fn=_guard_path,
    )
    rollback_preflight = inspect_rollback_structure(root, guard_fn=_guard_path)
    if candidates != _candidates(control):
        raise ProbeError("CONTROL_DIRECTORY_CHANGED")
    worker = worker_fn()
    matches = worker.get("runtime_source_sha") == version["source_sha"]
    live = (matches and status.get("ready") is True and now - stamp <= 300
            and type(status.get("supervisor_pid")) is int and status["supervisor_pid"] > 0
            and all(worker.get(k) is True for k in ("fresh", "eligible", "online", "auth_valid")))
    return {
        "installed_source_sha": version["source_sha"],
        "version_file_sha256": version_digest,
        "status_fresh": now - stamp <= 300,
        "supervisor_status_ready": status.get("ready") is True,
        "supervisor_pid_recorded": type(status.get("supervisor_pid")) is int and status["supervisor_pid"] > 0,
        "pending_refresh_present": "refresh-runtime.request.json" in names,
        "applied_receipt_present": "refresh-runtime.applied.json" in names,
        "failure_receipt_count": sum(p.startswith("refresh-runtime.failed.") for p in names),
        "original_receipt_identity_verified": False,
        "failure_inventory": failure_inventory,
        "rollback_preflight": rollback_preflight,
        "worker": worker,
        "file_worker_sha_match": matches,
        "live_state_consistent": live,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True, choices=(CONFIRM,))
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    result: dict[str, Any] = {
        "schema_version": 1, "result": "SUPERVISOR_READBACK_BLOCKED",
        "host": EXPECTED_HOST, "repository": REPOSITORY, "runner_name": RUNNER,
        "source_sha": os.getenv("GITHUB_SHA", ""), "correlation_id": args.correlation_id[:128],
        "read_only": True, "recovery_allowed": False,
        "origin_cryptographically_attested": False, "production_touched": False,
        "secrets_read": False,
    }
    exit_code = 2
    try:
        if (os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold()
                or os.getenv("GITHUB_REPOSITORY") != REPOSITORY or os.getenv("RUNNER_NAME") != RUNNER
                or not SHA_RE.fullmatch(result["source_sha"])):
            raise ProbeError("RUNNER_OR_HOST_INVALID")
        if not CID_RE.fullmatch(args.correlation_id):
            raise ProbeError("CORRELATION_INVALID")
        facts = collect()
        result.update(facts)
        if not facts["live_state_consistent"]:
            raise ProbeError("LIVE_STATE_MISMATCH")
        result["result"] = "SUPERVISOR_READBACK_OBSERVED"
        exit_code = 0
    except (ProbeError, OSError, ValueError) as exc:
        result["blocker_code"] = str(exc) if isinstance(exc, ProbeError) else "FIXED_READBACK_UNAVAILABLE"
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
