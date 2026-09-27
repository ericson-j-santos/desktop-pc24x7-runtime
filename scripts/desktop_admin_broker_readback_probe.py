#!/usr/bin/env python3
"""Probe hospedado e somente leitura do readback diagnóstico do Admin Broker."""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOPIC = "desktop-pc24x7-runtime-readback-v1-4c7d9a21b62f4e9a"
ENDPOINT = f"https://ntfy.sh/{TOPIC}/json?poll=1&since=latest"
EXPECTED_HOST = "DESKTOP-PDQK954"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_RESPONSE_BYTES = 262144
SAFE_RESULT_KEYS = {
    "handler",
    "bootstrap_state",
    "runner_running",
    "runner_registry_status",
    "runner_registry_labels_ok",
    "runner_registered_now",
    "runner_started_now",
    "github_pickup_required",
    "local_recovery_ok",
    "control_plane_runner_status",
    "control_plane_runner_started",
    "control_plane_runner_recovery_ok",
    "control_plane_rdc_recovery_ok",
    "watchdog_persistence_status",
    "watchdog_persistence_ok",
}


class ProbeError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ProbeError("readback_generated_at_invalid") from exc
    if parsed.tzinfo is None:
        raise ProbeError("readback_generated_at_invalid")
    return parsed.astimezone(timezone.utc)


def _safe_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in SAFE_RESULT_KEYS if key in value}


def validate_message(
    event: dict[str, Any],
    *,
    max_age_seconds: int,
    reference_time: datetime | None = None,
) -> dict[str, Any]:
    if event.get("event") != "message" or event.get("topic") != TOPIC:
        raise ProbeError("ntfy_message_not_allowed")
    message = event.get("message")
    if not isinstance(message, str):
        raise ProbeError("ntfy_message_payload_missing")
    try:
        payload = json.loads(message)
    except json.JSONDecodeError as exc:
        raise ProbeError("ntfy_message_payload_invalid") from exc
    if not isinstance(payload, dict):
        raise ProbeError("ntfy_message_payload_invalid")
    if payload.get("trust") != "diagnostic_only":
        raise ProbeError("readback_trust_invalid")
    if payload.get("authoritative_success") is not False:
        raise ProbeError("readback_authority_invalid")
    if str(payload.get("host") or "").casefold() != EXPECTED_HOST.casefold():
        raise ProbeError("readback_host_invalid")
    source_sha = str(payload.get("source_sha") or "").lower()
    if not SHA_RE.fullmatch(source_sha):
        raise ProbeError("readback_source_sha_invalid")
    if payload.get("production_touched") is not False or payload.get("secrets_read") is not False:
        raise ProbeError("readback_safety_invariant_failed")

    reference = reference_time or datetime.now(timezone.utc)
    generated = _parse_iso(payload.get("generated_at"))
    age = (reference - generated).total_seconds()
    if age < -60 or age > max_age_seconds:
        raise ProbeError("readback_not_fresh")

    comment_id = payload.get("comment_id")
    if not isinstance(comment_id, int) or comment_id <= 0:
        raise ProbeError("readback_comment_id_invalid")

    return {
        "schema_version": "1",
        "ok": True,
        "result": "DESKTOP_ADMIN_BROKER_READBACK_OBSERVED",
        "generated_at": now_iso(),
        "host": EXPECTED_HOST,
        "source_sha": source_sha,
        "comment_id": comment_id,
        "action": str(payload.get("action") or "")[:80],
        "status": str(payload.get("status") or "unknown")[:40],
        "broker_generated_at": generated.isoformat(),
        "readback_age_seconds": round(max(age, 0.0), 3),
        "ntfy_message_id": str(event.get("id") or "")[:32],
        "result_summary": _safe_result(payload.get("result")),
        "trust": "diagnostic_only",
        "authoritative_success": False,
        "production_touched": False,
        "secrets_read": False,
    }


def fetch_latest(timeout_seconds: float = 10.0) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        ENDPOINT,
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": "Desktop-PC24x7-Runtime-Readback-Probe/1.0",
        },
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=max(1.0, min(timeout_seconds, 20.0)),
        ) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ProbeError(f"ntfy_http_{int(exc.code)}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise ProbeError("ntfy_transport_unavailable") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProbeError("ntfy_response_too_large")

    events: list[dict[str, Any]] = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProbeError("ntfy_response_invalid") from exc
        if isinstance(item, dict):
            events.append(item)
    return events


def probe(*, max_age_seconds: int, timeout_seconds: float = 10.0) -> dict[str, Any]:
    if not 30 <= max_age_seconds <= 3600:
        raise ProbeError("max_age_seconds_out_of_range")
    events = fetch_latest(timeout_seconds)
    candidates = [
        item for item in events
        if item.get("event") == "message" and item.get("topic") == TOPIC
    ]
    if not candidates:
        raise ProbeError("ntfy_message_missing")
    return validate_message(candidates[-1], max_age_seconds=max_age_seconds)


def write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-file", type=Path, required=True)
    parser.add_argument("--max-age-seconds", type=int, default=900)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    args = parser.parse_args()
    try:
        evidence = probe(
            max_age_seconds=args.max_age_seconds,
            timeout_seconds=args.timeout_seconds,
        )
    except (ProbeError, UnicodeDecodeError, OSError, ValueError) as exc:
        evidence = {
            "schema_version": "1",
            "ok": False,
            "result": "DESKTOP_ADMIN_BROKER_READBACK_BLOCKED",
            "generated_at": now_iso(),
            "reason": str(exc)[:160],
            "host": EXPECTED_HOST,
            "trust": "diagnostic_only",
            "authoritative_success": False,
            "production_touched": False,
            "secrets_read": False,
        }
        write_evidence(args.evidence_file.resolve(), evidence)
        print(json.dumps(evidence, sort_keys=True))
        return 2

    write_evidence(args.evidence_file.resolve(), evidence)
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
