#!/usr/bin/env python3
"""Adaptador físico governado para o E2E do TODO dispatcher no Desktop PC24x7."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHA40 = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_HOST = "DESKTOP-PDQK954"
EXPECTED_RUNNER = "DESKTOP-PDQK954-runtime"
HARNESS_RELATIVE = Path("scripts/github_schedule_bridge_e2e.py")


class DispatcherE2EError(RuntimeError):
    pass


def validate_sha(value: str, reason: str) -> str:
    normalized = str(value or "").strip().lower()
    if not SHA40.fullmatch(normalized):
        raise DispatcherE2EError(reason)
    return normalized


def git_sha(repo_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            text=True,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise DispatcherE2EError("git_sha_probe_failed") from exc
    return validate_sha(completed.stdout.strip(), "git_sha_invalid")


def validate_runtime_identity(env: dict[str, str] | None = None) -> None:
    source = os.environ if env is None else env
    if source.get("COMPUTERNAME", "").strip().upper() != EXPECTED_HOST:
        raise DispatcherE2EError("unexpected_runtime_host")
    if source.get("RUNNER_NAME", "").strip() != EXPECTED_RUNNER:
        raise DispatcherE2EError("unexpected_runtime_runner")


def resolve_output_path(path: Path, *, base: Path | None = None) -> Path:
    if path.is_absolute():
        return path
    return ((base or Path.cwd()) / path).resolve()


def parse_last_json(stdout: str) -> dict[str, Any]:
    for raw in reversed(stdout.splitlines()):
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise DispatcherE2EError("dispatcher_e2e_evidence_missing")


def validate_dispatcher_evidence(payload: dict[str, Any], expected_rules_sha: str) -> None:
    checks = {
        "contract": payload.get("contract") == "github-hourly-todo-bridge-e2e",
        "rules_sha": payload.get("head_sha") == expected_rules_sha,
        "ready": payload.get("ready") is True,
        "selected_p0": payload.get("selected_idempotency_key") == payload.get("positive_idempotency_key"),
        "single_dispatch": payload.get("first_cycle_requested") == 1,
        "capacity_guard": payload.get("skipped_by_capacity") == 1,
        "lower_not_dispatched": payload.get("lower_continuation_count") == 0,
        "positive_terminal": payload.get("positive_continuation_state") == "COMPLETED",
        "positive_event_unique": payload.get("positive_event_count") == 1,
        "positive_continuation_unique": payload.get("positive_continuation_count") == 1,
        "replay_no_new_dispatch": payload.get("replay_cycle_requested") == 0,
        "replay_existing": payload.get("replay_existing") == 1,
        "scheduler_replay_idempotent": payload.get("scheduler_replay_duplicate") is True,
        "negative_not_dispatched": payload.get("negative_requested") == 0,
        "negative_untyped": payload.get("negative_skipped_untyped") == 1,
        "negative_no_continuation": payload.get("negative_continuation_count") == 0,
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise DispatcherE2EError("dispatcher_e2e_evidence_mismatch:" + ",".join(failed))


def write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def run_physical_e2e(
    *,
    expected_runtime_sha: str,
    expected_rules_sha: str,
    rules_root: Path,
    correlation_id: str,
    output: Path,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    validate_runtime_identity(env)
    runtime_sha = validate_sha(expected_runtime_sha, "expected_runtime_sha_invalid")
    rules_sha = validate_sha(expected_rules_sha, "expected_rules_sha_invalid")
    actual_runtime_sha = git_sha(ROOT)
    actual_rules_sha = git_sha(rules_root)
    if actual_runtime_sha != runtime_sha:
        raise DispatcherE2EError("runtime_sha_mismatch")
    if actual_rules_sha != rules_sha:
        raise DispatcherE2EError("rules_sha_mismatch")

    harness = rules_root / HARNESS_RELATIVE
    if not harness.is_file():
        raise DispatcherE2EError("dispatcher_e2e_harness_missing")

    child_env = dict(os.environ if env is None else env)
    current_pythonpath = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = str(rules_root) + (os.pathsep + current_pythonpath if current_pythonpath else "")

    try:
        completed = subprocess.run(
            [sys.executable, str(harness)],
            cwd=rules_root,
            env=child_env,
            text=True,
            capture_output=True,
            timeout=150,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DispatcherE2EError("dispatcher_e2e_execution_failed") from exc
    if completed.returncode != 0:
        raise DispatcherE2EError(f"dispatcher_e2e_nonzero:{completed.returncode}")

    payload = parse_last_json(completed.stdout)
    validate_dispatcher_evidence(payload, rules_sha)

    resolved_output = resolve_output_path(output)
    result = {
        "schema_version": "1.0.0",
        "result": "TODO_DISPATCHER_PHYSICAL_E2E_PASSED",
        "host": EXPECTED_HOST,
        "runner": EXPECTED_RUNNER,
        "runtime_sha": runtime_sha,
        "rules_sha": rules_sha,
        "correlation_id": correlation_id,
        "dispatcher_contract": payload["contract"],
        "positive_event_id": payload["positive_event_id"],
        "positive_idempotency_key": payload["positive_idempotency_key"],
        "selected_idempotency_key": payload["selected_idempotency_key"],
        "positive_continuation_state": payload["positive_continuation_state"],
        "first_cycle_requested": payload["first_cycle_requested"],
        "skipped_by_capacity": payload["skipped_by_capacity"],
        "lower_continuation_count": payload["lower_continuation_count"],
        "replay_cycle_requested": payload["replay_cycle_requested"],
        "scheduler_replay_duplicate": payload["scheduler_replay_duplicate"],
        "negative_continuation_count": payload["negative_continuation_count"],
        "independent_readback": (
            payload["positive_event_count"] == 1
            and payload["positive_continuation_count"] == 1
        ),
        "secrets_exposed": False,
        "production_touched": False,
        "deploy_executed": False,
        "reboot_executed": False,
    }
    write_evidence(resolved_output, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E físico do TODO dispatcher Pareto no Desktop")
    parser.add_argument("--expected-runtime-sha", required=True)
    parser.add_argument("--expected-rules-sha", required=True)
    parser.add_argument("--rules-root", type=Path, required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/todo-dispatcher-physical-e2e/evidence.json"),
    )
    args = parser.parse_args()
    output = resolve_output_path(args.output)

    try:
        result = run_physical_e2e(
            expected_runtime_sha=args.expected_runtime_sha,
            expected_rules_sha=args.expected_rules_sha,
            rules_root=args.rules_root.resolve(),
            correlation_id=args.correlation_id,
            output=output,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except DispatcherE2EError as exc:
        blocked = {
            "schema_version": "1.0.0",
            "result": "TODO_DISPATCHER_PHYSICAL_E2E_BLOCKED",
            "reason": str(exc)[:200],
            "correlation_id": args.correlation_id,
            "secrets_exposed": False,
            "production_touched": False,
            "deploy_executed": False,
            "reboot_executed": False,
        }
        write_evidence(output, blocked)
        print(json.dumps(blocked, ensure_ascii=True, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
