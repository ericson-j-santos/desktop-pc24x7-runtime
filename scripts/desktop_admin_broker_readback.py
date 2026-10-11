#!/usr/bin/env python3
"""Readback diagnóstico, sanitizado e outbound-only do Desktop runtime broker.

Este canal nunca prova sucesso funcional. A prova terminal do runner continua
sendo um pickup físico independente do GitHub Actions.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

TOPIC = "desktop-pc24x7-runtime-readback-v1-4c7d9a21b62f4e9a"
ENDPOINT = f"https://ntfy.sh/{TOPIC}"
EXPECTED_HOST = "DESKTOP-PDQK954"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_result_summary(accepted: dict[str, Any]) -> dict[str, Any]:
    outcome = accepted.get("outcome")
    if not isinstance(outcome, dict):
        return {}
    result = outcome.get("result")
    if not isinstance(result, dict):
        return {}

    summary: dict[str, Any] = {}
    for key in (
        "handler",
        "bootstrap_state",
        "runner_running",
        "runner_registry_status",
        "runner_registry_labels_ok",
        "runner_registered_now",
        "runner_started_now",
        "github_pickup_required",
        "local_recovery_ok",
        "refresh_state",
        "previous_source_sha",
        "target_source_sha",
        "new_broker_started",
    ):
        if key in result:
            summary[key] = result[key]

    cycle = result.get("cycle")
    if isinstance(cycle, dict):
        runner = cycle.get("github_runner")
        if isinstance(runner, dict):
            summary["control_plane_runner_status"] = runner.get("status")
            summary["control_plane_runner_started"] = runner.get("started")
        summary["control_plane_runner_recovery_ok"] = bool(
            cycle.get("runner_recovery_ok")
        )
        summary["control_plane_rdc_recovery_ok"] = bool(
            cycle.get("rdc_recovery_ok")
        )

    activation = result.get("activation")
    if isinstance(activation, dict):
        summary["watchdog_persistence_status"] = activation.get("status")
        summary["watchdog_persistence_ok"] = bool(activation.get("ok"))

    if result.get("handler") == "status":
        receipt = result.get("supervisor_receipt")
        if isinstance(receipt, dict):
            state = receipt.get("state")
            if type(state) is str and state in _RECEIPT_STATES:
                summary["supervisor_receipt_state"] = state
                code = receipt.get("error_code")
                if state == "failed" and type(code) is str and code in set(_ERROR_CODES.values()) | {"unknown"}:
                    summary["supervisor_receipt_error_code"] = code
    return summary


def build_payload(
    *,
    accepted: dict[str, Any],
    source_sha: str,
    host: str,
) -> dict[str, Any]:
    if host.casefold() != EXPECTED_HOST.casefold():
        raise ValueError("host_not_allowed")
    if len(source_sha) != 40 or any(
        ch not in "0123456789abcdefABCDEF" for ch in source_sha
    ):
        raise ValueError("source_sha_invalid")

    payload: dict[str, Any] = {
        "schema_version": "1",
        "generated_at": now_iso(),
        "trust": "diagnostic_only",
        "authoritative_success": False,
        "host": EXPECTED_HOST,
        "source_sha": source_sha.lower(),
        "comment_id": int(accepted.get("comment_id") or 0),
        "action": str(accepted.get("action") or "")[:80],
        "status": str(accepted.get("status") or "unknown")[:40],
        "production_touched": False,
        "secrets_read": False,
    }
    if accepted.get("status") == "failed":
        payload["error_code"] = str(
            accepted.get("error_code") or "broker_action_failed"
        )[:120]
    payload["result"] = _safe_result_summary(accepted)
    return payload


def publish_readback(
    *,
    accepted: dict[str, Any],
    source_sha: str,
    host: str,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    payload = build_payload(
        accepted=accepted,
        source_sha=source_sha,
        host=host,
    )
    body = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Title": "desktop-runtime-readback",
            "Tags": "computer",
            "User-Agent": "Desktop-PC24x7-Runtime-Broker-Readback/1.0",
        },
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=max(1.0, min(timeout_seconds, 10.0)),
        ) as response:
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
    except (OSError, urllib.error.URLError):
        return {
            "published": False,
            "channel": "ntfy",
            "authoritative": False,
            "error_code": "readback_transport_unavailable",
        }

    return {
        "published": 200 <= status < 300,
        "channel": "ntfy",
        "authoritative": False,
        "http_status": status,
    }

# Exact-scope, non-authoritative supervisor receipt metadata for owner status.
# No arbitrary path, host, SHA or correlation is accepted over GitHub comments.
import math
import os
import re
import socket
import time
from pathlib import Path

_SUPERVISOR_CONTROL = Path(r"C:\dev\chatgpt-workers\reqsys-orchestrator-24x7-runtime\data\control")
_SUPERVISOR_CORRELATION = "desktop-crlf-refresh-20261008-2116"
_SUPERVISOR_SHA = "0426ea5283a511e7e98b8396e65fc6cf6cb1e620"
_FAILURE_RECEIPT = re.compile(r"refresh-runtime\.failed\.\d{1,16}\.json\Z")
_RECEIPT_STATES = frozenset({"unavailable", "missing", "pending", "applied", "failed", "ambiguous", "invalid"})
_ERROR_CODES = {
    "stable bootstrap unavailable": "bootstrap_unavailable",
    "stable bootstrap import failed": "bootstrap_import_failed",
    "stable bootstrap contract invalid": "bootstrap_contract_invalid",
    "stable bootstrap refresh failed": "bootstrap_failed",
    "runtime refresh independent readback mismatch": "readback_mismatch",
    "source_root origin is not approved": "origin_mismatch",
    "runtime refresh request expired": "request_expired",
}


def _status_of_fixed_receipt(control: Path) -> dict[str, str]:
    """Read fixed receipt names and return only approved static codes."""
    try:
        if control.is_symlink() or not control.is_dir():
            return {"state": "unavailable"}
        info = control.lstat()
        if getattr(info, "st_file_attributes", 0) & 0x400:
            return {"state": "unavailable"}
        found = []
        with os.scandir(control) as items:
            for index, entry in enumerate(items):
                if index >= 256:
                    return {"state": "ambiguous"}
                if entry.name not in {"refresh-runtime.request.json", "refresh-runtime.applied.json"} and not _FAILURE_RECEIPT.fullmatch(entry.name):
                    continue
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    return {"state": "invalid"}
                metadata = entry.stat(follow_symlinks=False)
                if metadata.st_size > 8192 or getattr(metadata, "st_file_attributes", 0) & 0x400:
                    return {"state": "invalid"}
                with open(entry.path, "rb") as stream:
                    raw = stream.read(8193)
                    second = os.fstat(stream.fileno())
                if len(raw) > 8192 or second.st_size != metadata.st_size or second.st_mtime_ns != metadata.st_mtime_ns:
                    return {"state": "invalid"}
                try:
                    record = json.loads(raw.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    return {"state": "invalid"}
                if not isinstance(record, dict) or record.get("correlation_id") != _SUPERVISOR_CORRELATION:
                    continue
                if record.get("target_host") != EXPECTED_HOST or record.get("expected_sha") != _SUPERVISOR_SHA:
                    return {"state": "invalid"}
                key = "requested_at_epoch" if entry.name.endswith("request.json") else ("applied_at_epoch" if entry.name.endswith("applied.json") else "failed_at_epoch")
                stamp = record.get(key)
                if type(stamp) not in (int, float) or not math.isfinite(stamp) or not (0 < stamp < time.time() + 60):
                    return {"state": "invalid"}
                if entry.name.endswith("request.json") and record.get("version") == 1:
                    found.append({"state": "pending"})
                elif entry.name.endswith("applied.json") and record.get("schema_version") == 1 and record.get("source_sha") == _SUPERVISOR_SHA and record.get("readback_verified") is True:
                    found.append({"state": "applied"})
                elif _FAILURE_RECEIPT.fullmatch(entry.name) and record.get("schema_version") == 1:
                    error = record.get("error")
                    code = _ERROR_CODES.get(error, "unknown") if isinstance(error, str) else "unknown"
                    found.append({"state": "failed", "error_code": code})
                else:
                    return {"state": "invalid"}
        if len(found) > 1:
            return {"state": "ambiguous"}
        return found[0] if found else {"state": "missing"}
    except (OSError, ValueError, TypeError):
        return {"state": "unavailable"}


def supervisor_receipt_status() -> dict[str, str]:
    if os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold():
        return {"state": "unavailable"}
    return _status_of_fixed_receipt(_SUPERVISOR_CONTROL)
