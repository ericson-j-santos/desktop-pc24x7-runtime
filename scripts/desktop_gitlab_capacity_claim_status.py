#!/usr/bin/env python3
"""Read-only, request-scoped inspection of the original Desktop GitLab capacity claim.

Never creates, deletes, retries or changes an audit claim. Its output is a
sanitized observation, not permission to repeat the capacity request.
Invoke only via a validated Desktop Session Launcher and Command Gateway risk 1.
"""
from __future__ import annotations

import json
import os
import platform
import socket
import stat
from pathlib import Path
from typing import Callable

import desktop_gitlab_capacity_claim as claim

HOST = "DESKTOP-PDQK954"
ORIGINAL_REQUEST_ID = "d8b7342a-fc1e-445e-82af-2f6ae2319728"
ORIGINAL_SOURCE_SHA = "8aa192cbf7712c1da72a4b37dcb3ad3693ae5130"
ORIGINAL_RULES_SHA = "11e2e86d0283e83247d8058d05bbabe3dd7cc2c2"
ORIGINAL_ISSUE_NUMBER = "128"
MAX_BYTES = 4096
RECEIPT_KEYS = {
    "request_id", "source_sha", "rules_sha", "issue_id", "issue_number",
    "run_id", "run_attempt", "host", "schema", "state",
    "audit_state_changed", "configuration_changed",
}


class ReadbackRejected(ValueError):
    pass


def _require(condition: bool) -> None:
    if not condition:
        raise ReadbackRejected("CLAIM_READBACK_REJECTED")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    fields = {}
    for key, value in pairs:
        _require(key not in fields)
        fields[key] = value
    return fields


def _receipt(status: str, present: bool) -> dict:
    _require(status in {"CLAIM_PRESENT_UNCERTAIN", "CLAIM_ABSENT_AT_READ_TIME"})
    return {
        "schema_version": 1,
        "status": status,
        "host": HOST,
        "request_id": ORIGINAL_REQUEST_ID,
        "claim_present": present,
        "replay_authorized": False,
        "configuration_changed": False,
        "audit_state_changed": False,
        "secrets_accessed": False,
    }


def inspect(
    root: Path,
    *,
    guard: Callable = claim.windows_private_root,
    hostname: Callable[[], str] = socket.gethostname,
    system: Callable[[], str] = platform.system,
) -> dict:
    _require(hostname().upper() == HOST and system() == "Windows")
    with guard(root) as verify_file:
        claim.ordinary(root, True)
        target = root / f"desktop-capacity-{ORIGINAL_REQUEST_ID}.claim.json"
        try:
            before = claim.ordinary(target, False)
        except FileNotFoundError:
            # Absence is a point-in-time observation, NOT permission to retry.
            return _receipt("CLAIM_ABSENT_AT_READ_TIME", False)
        with target.open("rb") as stream:
            _require(callable(verify_file))
            verify_file(stream.fileno())
            opened = os.fstat(stream.fileno())
            _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1)
            raw = stream.read(MAX_BYTES + 1)
            opened_after = os.fstat(stream.fileno())
        after = claim.ordinary(target, False)
        _require(
            0 < len(raw) <= MAX_BYTES
            and (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)
            == (opened_after.st_dev, opened_after.st_ino)
            == (after.st_dev, after.st_ino)
            and before.st_size == opened.st_size == opened_after.st_size == after.st_size == len(raw)
        )
        try:
            data = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicate_keys)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReadbackRejected("CLAIM_READBACK_REJECTED") from exc
        _require(type(data) is dict and set(data) == RECEIPT_KEYS)
        try:
            claim.validate_metadata({k: data[k] for k in RECEIPT_KEYS - {
                "schema", "state", "audit_state_changed", "configuration_changed"
            }})
        except (ValueError, TypeError, KeyError) as exc:
            raise ReadbackRejected("CLAIM_READBACK_REJECTED") from exc
        _require(
            type(data["schema"]) is int
            and data["schema"] == 1
            and data["request_id"] == ORIGINAL_REQUEST_ID
            and data["source_sha"] == ORIGINAL_SOURCE_SHA
            and data["rules_sha"] == ORIGINAL_RULES_SHA
            and data["issue_number"] == ORIGINAL_ISSUE_NUMBER
            and data["host"] == HOST
            and data["state"] == "CLAIMED_UNCERTAIN"
            and data["audit_state_changed"] is True
            and data["configuration_changed"] is False
        )
        return _receipt("CLAIM_PRESENT_UNCERTAIN", True)


def main() -> int:
    # Caller may not specify a path, ID, SHA or host: fixed original audit only.
    try:
        base = os.environ["LOCALAPPDATA"]
        root = Path(base) / "ReqSys" / "CommandGateway"
        result = inspect(root)
    except Exception:
        # No exception type, message, raw JSON, or absolute path in output.
        print(json.dumps({"status": "CLAIM_READBACK_BLOCKED", "replay_authorized": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
