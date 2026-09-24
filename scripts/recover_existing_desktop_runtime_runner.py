#!/usr/bin/env python3
"""Recupera somente um runner dedicado já existente, sem registrar ou alterar labels."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import activate_desktop_runtime_runner as runtime


class ExistingRunnerRecoveryError(RuntimeError):
    pass


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def recover_existing(correlation_id: str) -> dict[str, Any]:
    host = runtime.validate_host()

    runner = runtime.discover_runner()
    if runner is None:
        raise ExistingRunnerRecoveryError("existing_runner_contract_missing")

    gh = runtime.find_gh()
    if gh is None:
        raise ExistingRunnerRecoveryError("github_cli_existing_install_required")

    runtime.ensure_gh_auth(gh, allow_interactive=False)
    registry_before = runtime.runner_registry_snapshot(gh)
    if not registry_before.get("present"):
        raise ExistingRunnerRecoveryError("existing_runner_registry_missing")
    if not registry_before.get("labels_ok"):
        raise ExistingRunnerRecoveryError("existing_runner_labels_mismatch")

    running_before = runtime.runner_running(runner)
    started_now = False
    restart_evidence: dict[str, Any] | None = None

    if not running_before:
        started_now = runtime.start_runner(runner)

    registry_after_start = runtime.wait_runner_registry_online(gh, timeout_seconds=8.0)
    running_after_start = runtime.runner_running(runner)

    if (
        running_after_start
        and registry_after_start.get("present")
        and registry_after_start.get("labels_ok")
        and registry_after_start.get("status") == "offline"
    ):
        restart_evidence = runtime.restart_runner(runner)
        registry_final = runtime.wait_runner_registry_online(gh, timeout_seconds=30.0)
    else:
        registry_final = registry_after_start

    running_final = runtime.runner_running(runner)
    ok = bool(
        running_final
        and registry_final.get("present")
        and registry_final.get("labels_ok")
        and registry_final.get("status") == "online"
    )

    return {
        "ok": ok,
        "state": "existing_runner_online" if ok else "existing_runner_not_online",
        "host": host,
        "correlation_id": correlation_id,
        "runner_name": runtime.RUNNER_NAME,
        "runner_scope": runtime.REPOSITORY,
        "runner_home_contract_present": True,
        "runner_running_before": running_before,
        "runner_started_now": started_now,
        "runner_restarted_offline": restart_evidence is not None,
        "runner_running_final": running_final,
        "registry_present_before": bool(registry_before.get("present")),
        "registry_status_before": str(registry_before.get("status") or "unknown"),
        "registry_labels_ok_before": bool(registry_before.get("labels_ok")),
        "registry_present_final": bool(registry_final.get("present")),
        "registry_status_final": str(registry_final.get("status") or "unknown"),
        "registry_labels_ok_final": bool(registry_final.get("labels_ok")),
        "registration_attempted": False,
        "registration_token_requested": False,
        "labels_mutated": False,
        "interactive_auth_used": False,
        "legacy_reqsys_runner_touched": False,
        "production_touched": False,
        "rdc_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()

    if args.confirm != "RECOVER-EXISTING-DESKTOP-RUNTIME-RUNNER":
        payload = {
            "ok": False,
            "state": "confirmation_invalid",
            "correlation_id": args.correlation_id,
            "registration_attempted": False,
            "production_touched": False,
        }
        atomic_json(args.evidence_file, payload)
        print(json.dumps(payload, sort_keys=True))
        return 2

    try:
        payload = recover_existing(args.correlation_id.strip())
        code = 0 if payload["ok"] else 3
    except Exception as exc:
        payload = {
            "ok": False,
            "state": str(exc)[:200],
            "error_type": type(exc).__name__,
            "correlation_id": args.correlation_id.strip(),
            "registration_attempted": False,
            "registration_token_requested": False,
            "labels_mutated": False,
            "interactive_auth_used": False,
            "legacy_reqsys_runner_touched": False,
            "production_touched": False,
            "rdc_required": False,
        }
        code = 4

    atomic_json(args.evidence_file, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
