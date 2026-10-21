#!/usr/bin/env python3
"""Request-bound broker diagnostics; never authorizes Desktop execution."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

HOST = "DESKTOP-PDQK954"
EVIDENCE = Path(".tmp/reqsys-dev-broker-preflight/evidence.json")
SHA = re.compile(r"[0-9a-f]{40}")
SAFE_ERRORS = {
    "ntfy_message_missing", "ntfy_transport_unavailable",
    "readback_not_fresh", "ntfy_http_404", "ntfy_http_429",
}


class ReadbackError(ValueError):
    pass


def stamp(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ReadbackError("BROKER_TIMESTAMP_INVALID") from None
    if parsed.tzinfo is None:
        raise ReadbackError("BROKER_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


def validate(evidence: object, *, comment_id: int, issued_at: str,
             observed_at: str) -> dict[str, Any]:
    """Reject unrelated/latest responses and keep diagnostic trust explicit."""
    if type(comment_id) is not int or comment_id <= 0:
        raise ReadbackError("BROKER_REQUEST_INVALID")
    issued, observed = stamp(issued_at), stamp(observed_at)
    if not 0 <= (observed - issued).total_seconds() <= 1800:
        raise ReadbackError("BROKER_REQUEST_EXPIRED_OR_FUTURE")
    if not isinstance(evidence, dict):
        raise ReadbackError("BROKER_RESPONSE_INVALID")
    if (type(evidence.get("comment_id")) is not int
            or evidence["comment_id"] != comment_id):
        raise ReadbackError("BROKER_RESPONSE_COMMENT_MISMATCH")
    if (evidence.get("host") != HOST or evidence.get("action") != "status"
            or evidence.get("status") != "completed"
            or evidence.get("ok") is not True
            or evidence.get("result") != "DESKTOP_ADMIN_BROKER_READBACK_OBSERVED"
            or evidence.get("trust") != "diagnostic_only"
            or evidence.get("authoritative_success") is not False
            or evidence.get("production_touched") is not False
            or evidence.get("secrets_read") is not False):
        raise ReadbackError("BROKER_RESPONSE_CONTRACT_INVALID")
    source = evidence.get("source_sha")
    if type(source) is not str or SHA.fullmatch(source) is None:
        raise ReadbackError("BROKER_SOURCE_SHA_INVALID")
    generated = stamp(evidence.get("broker_generated_at"))
    if generated < issued or not 0 <= (observed - generated).total_seconds() <= 900:
        raise ReadbackError("BROKER_RESPONSE_STALE_OR_UNCORRELATED")
    summary = evidence.get("result_summary")
    if not isinstance(summary, dict) or summary.get("handler") != "status":
        raise ReadbackError("BROKER_HANDLER_INVALID")
    return {
        "schema_version": 1, "status": "observed",
        "reason": "REQUEST_BOUND_DIAGNOSTIC_OBSERVED",
        "host": HOST, "comment_id": comment_id,
        "requested_at": issued.isoformat(), "observed_at": observed.isoformat(),
        "broker_generated_at": generated.isoformat(), "broker_source_sha": source,
        "trust": "diagnostic_only", "origin_authenticated": False,
        "authoritative_success": False, "physical_ready": False,
        "runtime_e2e": False, "production_touched": False, "secrets_read": False,
    }


def read_diagnostic() -> dict[str, Any]:
    # Existing fixed-topic reader. No endpoint, token or command is accepted.
    from desktop_admin_broker_readback_probe import probe
    return probe(max_age_seconds=900, timeout_seconds=10)


def execute(env: Mapping[str, str], *, reader: Callable = read_diagnostic,
            observed_at: str | None = None, output: Path = EVIDENCE) -> dict[str, Any]:
    fixed_observation = observed_at
    observed_at = observed_at or datetime.now(timezone.utc).isoformat()
    result = {
        "schema_version": 1, "status": "blocked", "host": HOST,
        "reason": "BROKER_PREFLIGHT_UNVERIFIED",
        "trust": "diagnostic_only", "origin_authenticated": False,
        "authoritative_success": False, "physical_ready": False,
        "runtime_e2e": False, "production_touched": False, "secrets_read": False,
    }
    try:
        source = env.get("GITHUB_SHA", "")
        run_id = env.get("GITHUB_RUN_ID", "")
        if (SHA.fullmatch(source) is None or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id)
                or env.get("GITHUB_RUN_ATTEMPT") != "1"):
            raise ReadbackError("BROKER_EXECUTION_IDENTITY_INVALID")
        comment_id = env.get("EXPECTED_COMMENT_ID", "")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", comment_id):
            raise ReadbackError("BROKER_REQUEST_INVALID")
        issued = env.get("EXPECTED_ISSUED_AT")
        if not 0 <= (stamp(observed_at) - stamp(issued)).total_seconds() <= 1800:
            raise ReadbackError("BROKER_REQUEST_EXPIRED_OR_FUTURE")
        candidate = reader()
        # Timestamp after the bounded read, not before the remote response.
        observed_at = fixed_observation or datetime.now(timezone.utc).isoformat()
        result = validate(candidate, comment_id=int(comment_id),
                          issued_at=issued, observed_at=observed_at)
        result.update(source_runtime_sha=source, run_id=run_id)
    except ReadbackError as exc:
        result["reason"] = str(exc)
    except Exception as exc:
        # Never publish raw transport errors, URLs or arbitrary remote content.
        result["reason"] = str(exc) if str(exc) in SAFE_ERRORS else "BROKER_READBACK_UNAVAILABLE"
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return result


if __name__ == "__main__":
    receipt = execute(os.environ)
    print(json.dumps(receipt, sort_keys=True))
    raise SystemExit(0 if receipt["status"] == "observed" else 2)
