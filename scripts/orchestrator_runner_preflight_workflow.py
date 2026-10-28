#!/usr/bin/env python3
"""Fixed read-only orchestrator runner proof through the existing Gateway."""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
HOST = "DESKTOP-PDQK954"
RUNNER = "DESKTOP-PDQK954-runtime"
TARGET = "ericson-j-santos/reqsys-engineering-orchestrator"
SHA = re.compile(r"^[0-9a-f]{40}$")
PREFLIGHT_BLOCK_STATES = frozenset({
    "github_local_auth_required", "github_local_api_failed",
    "orchestrator_readback_unavailable", "orchestrator_http_not_ready",
    "orchestrator_not_ready", "orchestrator_desktop_worker_not_unique",
    "orchestrator_desktop_worker_not_ready",
})
FALSE_FIELDS = (
    "execution_authorized", "registration_performed", "registration_token_requested",
    "runner_started", "watchdog_changed", "runner_version_preflight_proven",
    "physical_pickup_proven", "continuous_operation_proven",
)


class WorkflowBlocked(RuntimeError):
    pass


def require(condition: bool, state: str) -> None:
    if not condition:
        raise WorkflowBlocked(state)


INVENTORY_STATUS_FIELDS = (
    "paths_status", "metadata_status", "task_query_status", "task_runtime_status",
    "task_identity_status", "state_status", "runtime_home_status",
    "orchestrator_home_status", "watchdog_inventory_status",
)
INVENTORY_BOOL_FIELDS = (
    "loopback_ready", "desktop_worker_fresh", "desktop_worker_controller_online",
    "desktop_worker_auth_valid", "desktop_worker_normal_profile",
    "metadata_host_matches", "metadata_runner_home_matches", "metadata_release_matches",
    "metadata_python_exists", "task_registered_observed", "task_at_startup",
    "task_enabled", "task_s4u", "task_limited",
    "process_user_matches_task_principal", "task_action_matches_installation",
    "state_ok", "state_source_matches_installation", "state_fresh_300s",
    "orchestrator_home_empty", "orchestrator_config_present",
)
INVENTORY_DIGEST_FIELDS = (
    "metadata_sha256", "watchdog_sha256", "uac_sha256",
    "launcher_sha256", "host_policy_sha256",
)
INVENTORY_FALSE_FIELDS = (
    "execution_authorized", "registration_performed", "registration_token_requested",
    "runner_started", "watchdog_changed",
)


def public_local_inventory(value, *, sha: str, correlation: str, state: str):
    """Project a verified failure supplement to a closed public schema."""
    if not (
        isinstance(value, dict) and type(value.get("schema_version")) is int
        and value.get("schema_version") == 1
        and value.get("kind") == "orchestrator-runner-local-inventory"
        and value.get("source_sha") == sha
        and value.get("correlation_id") == correlation
        and value.get("preflight_state") == state
        and state in PREFLIGHT_BLOCK_STATES
        and value.get("read_only") is True
        and all(value.get(key) is False for key in INVENTORY_FALSE_FIELDS)
    ):
        return None
    public = {
        "schema_version": 1, "kind": "orchestrator-runner-local-inventory",
        "source_sha": sha, "correlation_id": correlation,
        "preflight_state": state, "preflight_remains_blocked": True,
        "read_only": True, **{key: False for key in INVENTORY_FALSE_FIELDS},
    }
    statuses = {"observed", "missing", "invalid", "blocked", "unavailable"}
    for key in INVENTORY_STATUS_FIELDS:
        candidate = value.get(key)
        public[key] = candidate if isinstance(candidate, str) and candidate in statuses else "unavailable"
    for key in INVENTORY_BOOL_FIELDS:
        candidate = value.get(key)
        public[key] = candidate if type(candidate) is bool else None
    for key in INVENTORY_DIGEST_FIELDS:
        candidate = value.get(key)
        public[key] = candidate if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{64}", candidate) else None
    source = value.get("installed_source_sha")
    public["installed_source_sha"] = source if isinstance(source, str) and SHA.fullmatch(source) else None
    for key, minimum, maximum in (
        ("desktop_worker_matches", 0, 10000), ("runtime_unresolved_process_count", 0, 10000),
        ("runtime_listener_pid", 1, 0xFFFFFFFF), ("task_state", 0, 4),
    ):
        candidate = value.get(key)
        public[key] = candidate if type(candidate) is int and minimum <= candidate <= maximum else None
    for key, allowed in (
        ("github_cli_status", {"located", "not_located", "unavailable"}),
        ("github_owner_validation", {"not_validated", "validated_before_endpoint_failure", "not_checked_by_inventory"}),
        ("readyz_status", {"observed", "http_not_ready", "invalid_response", "unavailable"}),
        ("workers_status", {"observed", "http_not_ready", "invalid_response", "unavailable"}),
    ):
        candidate = value.get(key)
        public[key] = candidate if isinstance(candidate, str) and candidate in allowed else (
            "not_checked_by_inventory" if key == "github_owner_validation" else "unavailable"
        )
    return public


def gateway_payload(completed, *, sha: str, correlation: str, session: str, negative: bool) -> dict:
    expected_exit = 2 if negative or completed.returncode == 2 else 0
    try:
        event = json.loads(completed.stdout.strip().splitlines()[-1])
        payload = json.loads(event["stdout"])
        require(
            completed.returncode == expected_exit
            and event["action"] == "run"
            and type(event["risk"]) is int and event["risk"] == 1
            and event["session_id"] == session
            and event["correlation_id"] == correlation
            and event["gateway_exit_code"] == expected_exit
            and event["command_exit_code"] == expected_exit
            and event["state_changed"] is False
            and event["result"] == ("command_failed" if expected_exit == 2 else "ok")
            and event["before"]["head"] == sha == event["after"]["head"]
            and isinstance(payload, dict),
            "gateway_readback_rejected",
        )
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise WorkflowBlocked("gateway_readback_invalid") from None
    if not negative and expected_exit == 2:
        state = payload.get("state")
        readonly_block = (
            payload.get("ok") is False and payload.get("read_only") is True
            and payload.get("execution_authorized") is False
            and payload.get("registration_performed") is False
            and payload.get("registration_token_requested") is False
        )
        if readonly_block and isinstance(state, str) and state in PREFLIGHT_BLOCK_STATES:
            inventory = public_local_inventory(
                payload.get("local_inventory"), sha=sha, correlation=correlation, state=state,
            )
            if inventory is not None:
                print("ORCHESTRATOR_LOCAL_INVENTORY:" + json.dumps(
                    inventory, sort_keys=True, separators=(",", ":"),
                ))
            raise WorkflowBlocked("preflight_blocked:" + state)
        raise WorkflowBlocked("preflight_blocked:unclassified")
    if negative:
        require(
            payload.get("ok") is False
            and payload.get("state") == "source_sha_mismatch"
            and payload.get("read_only") is True
            and payload.get("execution_authorized") is False
            and payload.get("registration_performed") is False
            and payload.get("registration_token_requested") is False,
            "negative_sha_control_failed",
        )
        return payload
    profile = payload.get("profile")
    require(
        payload.get("ok") is True
        and payload.get("state") == "READ_ONLY_PLAN_RECORDED_EXECUTION_PENDING"
        and payload.get("mode") == "preflight_only"
        and payload.get("source_sha") == sha
        and payload.get("correlation_id") == correlation
        and payload.get("read_only") is True
        and isinstance(profile, dict)
        and profile.get("target") == "orchestrator-dev"
        and profile.get("environment") == "dev"
        and profile.get("repository") == TARGET
        and profile.get("host") == HOST
        and profile.get("runner_name") == HOST + "-orchestrator-dev"
        and all(payload.get(key) is False for key in FALSE_FIELDS),
        "preflight_receipt_rejected",
    )
    registration = payload.get("registration_required")
    runner_id = payload.get("observed_runner_id")
    require(
        (registration is True and runner_id is None)
        or (registration is False and type(runner_id) is int and runner_id > 0),
        "preflight_registration_state_invalid",
    )
    return payload


def prove() -> None:
    env = os.environ
    sha = env.get("ANCHOR_SHA", "")
    rules_sha = env.get("RULES_SHA", "")
    main_sha = env.get("ORCHESTRATOR_MAIN_SHA", "")
    correlation = env.get("CORRELATION_ID", "")
    require(
        env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REPOSITORY") == REPOSITORY
        and env.get("GITHUB_RUN_ATTEMPT") == "1"
        and env.get("GITHUB_SHA") == sha
        and SHA.fullmatch(sha) is not None
        and SHA.fullmatch(rules_sha) is not None
        and SHA.fullmatch(main_sha) is not None
        and env.get("RUNNER_NAME") == RUNNER
        and env.get("RUNNER_OS") == "Windows"
        and env.get("RUNNER_ARCH") == "X64"
        and socket.gethostname().upper() == HOST
        and re.fullmatch(r"dedicated-runner-[1-9][0-9]*-1", correlation) is not None,
        "workflow_identity_rejected",
    )
    session = env.get("SESSION_ID", "")
    require(bool(session) and not any(ch in session for ch in "\r\n"), "session_identity_invalid")
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    target = Path(env.get("TARGET_PATH", ""))
    require(workspace.is_absolute() and target.is_absolute(), "workflow_path_invalid")
    gateway = workspace / "_rules" / "scripts" / "command_gateway.py"
    policy = workspace / "_rules" / "config" / "command-gateway.policy.json"
    probe = target / "scripts" / "orchestrator_dev_runner_preflight.py"
    require(all(path.is_file() for path in (gateway, policy, probe)), "governed_files_missing")
    command = [
        sys.executable, "-B", str(gateway),
        "--policy", str(policy), "--correlation-id", correlation,
        "run", "--cwd", str(target), "--session-id", session,
        "--risk", "1", "--timeout", "120", "--expected-head", sha,
        "--", sys.executable, "-B", str(probe),
        "--expected-sha", sha, "--correlation-id", correlation,
    ]
    results = []
    for expected in ("0" * 40, sha, sha):
        invocation = list(command)
        invocation[invocation.index("--expected-sha") + 1] = expected
        try:
            completed = subprocess.run(
                invocation, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=150, check=False, shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise WorkflowBlocked("gateway_execution_unavailable") from None
        results.append(gateway_payload(
            completed, sha=sha, correlation=correlation, session=session,
            negative=expected != sha,
        ))
    require(results[1] == results[2], "preflight_replay_diverged")
    try:
        run_id = int(env["GITHUB_RUN_ID"])
        ci_run_id = int(env["ORCHESTRATOR_CI_RUN_ID"])
        ci_attempt = int(env["ORCHESTRATOR_CI_ATTEMPT"])
        source_pr = int(env["ORCHESTRATOR_SOURCE_PR"])
    except (KeyError, ValueError):
        raise WorkflowBlocked("admission_receipt_invalid") from None
    require(min(run_id, ci_run_id, ci_attempt) > 0 and source_pr >= 0, "admission_receipt_invalid")
    receipt = {
        "schema_version": 1,
        "kind": "orchestrator-runner-readonly-preflight",
        "source_sha": sha, "rules_sha": rules_sha, "main_sha": main_sha,
        "source_pr": source_pr, "ci_run_id": ci_run_id, "ci_attempt": ci_attempt,
        "run_id": run_id, "run_attempt": 1, "correlation_id": correlation,
        "host": HOST, "runner_name": RUNNER, "runner_id": 2,
        "target_repository": TARGET, "target_environment": "dev",
        "negative_state": results[0]["state"], "negative_exit_code": 2,
        "replay_identical": True, "gateway_state_unchanged": True,
        "read_only": True, "registration_required": results[1]["registration_required"],
        "observed_target_runner_id": results[1]["observed_runner_id"],
        **{key: False for key in FALSE_FIELDS},
    }
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    output = env.get("GITHUB_OUTPUT", "")
    require(bool(output), "github_output_missing")
    with Path(output).open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("receipt=" + raw + "\n")
    print("ORCHESTRATOR_PREFLIGHT_RECEIPT:" + raw)
