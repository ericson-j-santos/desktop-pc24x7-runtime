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
            "Content-Type": "application/json",
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
