from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

EXPECTED_SOURCE_HOST = "Noteri"
TARGET_HOST = "DESKTOP-PDQK954"
ENDPOINT = "http://DESKTOP-PDQK954:8787"
WORKER_ID = "desktop-pdqk954"
TASK_TYPE = "host.rdc.recover.v1"
CONFIRM = "RECOVER-DESKTOP-RDC-VIA-ORCHESTRATOR"
COMPLETED = "CONCLUÍDO"
TERMINAL_FAILURES = {"BLOQUEADO", "CANCELADO"}
EXPECTED_TASK = r"\Automation\RemoteDesktopCommander"
EXPECTED_LAUNCHER = r"C:\RemoteDesktopCommander\start-remote-desktop-commander.cmd"


class RecoveryError(RuntimeError):
    pass


def request_json(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any]]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(ENDPOINT + path, data=data, method=method, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return int(response.status), json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": f"http_{exc.code}"}
        return int(exc.code), body
    except URLError as exc:
        raise RecoveryError(
            f"control_plane_unavailable:{type(exc.reason).__name__}"
        ) from exc


def validate_source_host() -> str:
    if os.name != "nt":
        raise RecoveryError("windows_required")
    host = socket.gethostname()
    if host.casefold() != EXPECTED_SOURCE_HOST.casefold():
        raise RecoveryError(f"source_host_not_authorized:{host}")
    return host


def read_worker() -> dict[str, Any]:
    status, ready = request_json("GET", "/readyz")
    if status != 200 or ready.get("ready") is not True:
        raise RecoveryError(f"desktop_orchestrator_not_ready:http_{status}")

    status, snapshot = request_json("GET", "/v1/workers")
    if status != 200:
        raise RecoveryError(f"workers_read_failed:http_{status}")
    workers = snapshot.get("workers")
    if not isinstance(workers, list):
        raise RecoveryError("workers_payload_invalid")
    matches = [
        item for item in workers
        if isinstance(item, dict)
        and str(item.get("worker_id") or "").casefold() == WORKER_ID.casefold()
    ]
    if len(matches) != 1:
        raise RecoveryError(f"desktop_worker_count_invalid:{len(matches)}")
    worker = matches[0]
    if worker.get("fresh") is not True:
        raise RecoveryError("desktop_worker_not_fresh")
    if worker.get("controller_online") is not True:
        raise RecoveryError("desktop_controller_offline")
    if worker.get("auth_valid") is not True:
        raise RecoveryError("desktop_worker_auth_invalid")
    if str(worker.get("profile") or "").upper() != "NORMAL":
        raise RecoveryError(f"desktop_profile_not_normal:{worker.get('profile')}")
    capabilities = worker.get("capabilities")
    if not isinstance(capabilities, dict):
        raise RecoveryError("desktop_capabilities_invalid")
    safe = capabilities.get("safe_task_types")
    if not isinstance(safe, list) or TASK_TYPE not in safe:
        raise RecoveryError("rdc_recovery_capability_missing")
    return worker


def build_intake(correlation_id: str) -> dict[str, Any]:
    logical = f"{TASK_TYPE}|{TARGET_HOST}|{correlation_id}"
    digest = hashlib.sha256(logical.encode("utf-8")).hexdigest()[:24]
    return {
        "event_id": f"rdc-recover-{digest}",
        "correlation_id": correlation_id,
        "idempotency_key": f"rdc-recover-{digest}",
        "task_type": TASK_TYPE,
        "payload": {"target_host": TARGET_HOST, "force_restart": False},
        "risk": 2,
        "max_attempts": 1,
        "lease_seconds": 60,
    }


def submit(intake: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    status, response = request_json("POST", "/v1/intake", intake)
    if status not in {200, 201}:
        raise RecoveryError(
            f"rdc_recovery_submit_failed:http_{status}:{response.get('error')}"
        )
    item = response.get("item")
    if not isinstance(item, dict) or not item.get("id"):
        raise RecoveryError("rdc_recovery_item_missing")
    return status, response


def wait_terminal(item_id: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        status, body = request_json("GET", f"/v1/work-items/{item_id}")
        if status != 200:
            raise RecoveryError(f"work_item_read_failed:http_{status}")
        item = body.get("item")
        if not isinstance(item, dict):
            raise RecoveryError("work_item_payload_invalid")
        last = item
        state = item.get("status")
        if state == COMPLETED:
            return item
        if state in TERMINAL_FAILURES:
            raise RecoveryError(
                f"rdc_recovery_terminal_failure:{state}:{item.get('last_error')}"
            )
        time.sleep(1.0)
    raise RecoveryError(
        f"rdc_recovery_timeout:{last.get('status')}:{last.get('last_error')}"
    )


def validate_result(item: dict[str, Any]) -> dict[str, Any]:
    result = item.get("result")
    if not isinstance(result, dict):
        raise RecoveryError("rdc_recovery_result_missing")
    if result.get("handler") != TASK_TYPE:
        raise RecoveryError("rdc_recovery_handler_mismatch")
    if str(result.get("host") or "").casefold() != TARGET_HOST.casefold():
        raise RecoveryError("rdc_recovery_host_mismatch")
    if result.get("task") != EXPECTED_TASK:
        raise RecoveryError("rdc_recovery_task_mismatch")
    if result.get("launcher") != EXPECTED_LAUNCHER:
        raise RecoveryError("rdc_recovery_launcher_mismatch")
    after = result.get("after")
    if not isinstance(after, dict) or after.get("enabled") is not True:
        raise RecoveryError("rdc_recovery_after_invalid")
    if not str(result.get("running_instance") or "").strip():
        raise RecoveryError("rdc_recovery_instance_missing")
    return result


def execute(confirm: str, correlation_id: str, timeout_seconds: int) -> dict[str, Any]:
    if confirm != CONFIRM:
        raise RecoveryError("confirmation_invalid")
    if not 8 <= len(correlation_id.strip()) <= 160:
        raise RecoveryError("correlation_id_invalid")
    if timeout_seconds <= 0 or timeout_seconds > 120:
        raise RecoveryError("timeout_invalid")

    source = validate_source_host()
    worker_before = read_worker()
    intake = build_intake(correlation_id)

    _, first = submit(intake)
    item_id = str(first["item"]["id"])
    terminal = wait_terminal(item_id, timeout_seconds)
    result = validate_result(terminal)

    _, replay = submit(intake)
    replay_item = replay.get("item") or {}
    if str(replay_item.get("id") or "") != item_id:
        raise RecoveryError("rdc_recovery_replay_item_mismatch")
    if replay.get("replayed") is not True:
        raise RecoveryError("rdc_recovery_replay_not_idempotent")

    worker_after = read_worker()
    return {
        "schema_version": "1",
        "ok": True,
        "result": "DESKTOP_RDC_RECOVERY_REQUEST_VERIFIED",
        "source_host": source,
        "target_host": TARGET_HOST,
        "endpoint": ENDPOINT,
        "task_type": TASK_TYPE,
        "item_id": item_id,
        "replayed": True,
        "rdc_task_started": True,
        "worker_instance_id_before": (
            (worker_before.get("capabilities") or {}).get("worker_instance_id")
        ),
        "worker_instance_id_after": (
            (worker_after.get("capabilities") or {}).get("worker_instance_id")
        ),
        "production_touched": False,
        "secrets_read": False,
        "remote_shell_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--evidence-file", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    args = parser.parse_args()
    args.evidence_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        payload = execute(
            args.confirm,
            args.correlation_id,
            args.timeout_seconds,
        )
        code = 0
    except Exception as exc:
        payload = {
            "schema_version": "1",
            "ok": False,
            "result": "DESKTOP_RDC_RECOVERY_BLOCKED",
            "source_host": socket.gethostname(),
            "target_host": TARGET_HOST,
            "endpoint": ENDPOINT,
            "task_type": TASK_TYPE,
            "error_type": type(exc).__name__,
            "error_code": str(exc)[:500],
            "production_touched": False,
            "secrets_read": False,
            "remote_shell_used": False,
        }
        code = 2
    args.evidence_file.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
