#!/usr/bin/env python3
"""Classify local GitHub CLI auth and existing watchdog identity without secrets."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.dont_write_bytecode = True

import bootstrap_dedicated_runtime_runner as bootstrap
import desktop_control_plane_watchdog as watchdog
import orchestrator_dev_runner_preflight as preflight

OWNER = "ericson-j-santos"
IDENTITY_FIELDS = (
    "task_query_status", "task_registered_observed", "task_at_startup",
    "task_runtime_status", "task_state", "task_enabled",
    "task_identity_status", "task_s4u", "task_limited",
    "process_user_matches_task_principal",
    "task_action_matches_installation",
)


def classify_auth_status(payload: object, returncode: int) -> str:
    if not isinstance(payload, dict):
        return "auth_status_unavailable"
    hosts = payload.get("hosts")
    if not isinstance(hosts, dict):
        return "auth_status_unavailable"
    entries = hosts.get("github.com", [])
    if not isinstance(entries, list):
        return "auth_status_unavailable"
    active = [item for item in entries if isinstance(item, dict) and item.get("active") is True]
    if not active:
        return "credential_unavailable"
    if len(active) != 1:
        return "auth_state_ambiguous"
    item = active[0]
    state = item.get("state")
    if state == "success":
        if returncode != 0:
            return "auth_state_ambiguous"
        login = item.get("login")
        if not isinstance(login, str) or not login:
            return "auth_state_ambiguous"
        return "owner_candidate" if login.casefold() == OWNER.casefold() else "account_mismatch"
    if state in ("error", "refresh_expired"):
        return "authentication_invalid"
    if state == "timeout":
        return "github_endpoint_unavailable"
    return "auth_state_ambiguous"


def diagnose_auth() -> tuple[str, bool, bool]:
    binary = bootstrap.find_gh()
    if binary is None:
        return "cli_unavailable", False, False
    env = bootstrap.gh_env()
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    env["GH_HOST"] = "github.com"
    env["GH_PROMPT_DISABLED"] = "1"
    try:
        result = subprocess.run(
            [str(binary), "auth", "status", "--active", "--hostname", "github.com",
             "--json", "hosts", "--no-refresh"],
            env=env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "auth_status_unavailable", True, False
    try:
        payload = json.loads(result.stdout)
    except (ValueError, TypeError):
        payload = None
    state = classify_auth_status(payload, result.returncode)
    if state in ("auth_status_unavailable", "auth_state_ambiguous"):
        try:
            token_probe = subprocess.run(
                [str(binary), "auth", "token", "--hostname", "github.com"],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "credential_probe_unavailable", True, False
        if token_probe.returncode != 0:
            return "credential_unavailable", True, False
        state = "owner_candidate"
    if state not in ("owner_candidate", "account_mismatch"):
        return state, True, False
    try:
        api = subprocess.run(
            [str(binary), "api", "user", "--jq", ".login"],
            env=env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "github_endpoint_unavailable", True, False
    if api.returncode != 0:
        detail = (api.stderr or "").casefold()
        if "http 401" in detail or "bad credentials" in detail or "401 unauthorized" in detail:
            return "authentication_invalid", True, False
        return "api_failure_unclassified", True, False
    if api.stdout.strip().casefold() != OWNER.casefold():
        return "account_mismatch", True, False
    return "owner_validated", True, True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    receipt = {
        "schema_version": 1,
        "kind": "orchestrator-local-gh-auth-and-supervision-diagnostic",
        "source_sha": args.expected_sha if preflight.SHA_RE.fullmatch(args.expected_sha) else None,
        "correlation_id": args.correlation_id if preflight.CORRELATION_RE.fullmatch(args.correlation_id) else None,
        "host": "DESKTOP-PDQK954",
        "read_only": True,
        "registration_performed": False,
        "runner_started": False,
        "watchdog_changed": False,
        "auth_classification": "not_checked",
        "gh_located": None,
        "owner_validated": False,
        "supervision": {key: None for key in IDENTITY_FIELDS},
    }
    try:
        if receipt["source_sha"] is None or receipt["correlation_id"] is None:
            raise ValueError("invalid_request")
        preflight.require_source(args.expected_sha)
        if bootstrap.validate_host().casefold() != receipt["host"].casefold():
            raise ValueError("host_mismatch")
        receipt["state_validated"] = True
        state, located, owner_validated = diagnose_auth()
        receipt["auth_classification"] = state
        receipt["gh_located"] = located
        receipt["owner_validated"] = owner_validated
        try:
            inventory = watchdog.readonly_local_inventory()
            receipt["supervision"] = {key: inventory.get(key) for key in IDENTITY_FIELDS}
        except Exception:
            receipt["supervision_status"] = "unavailable"
        else:
            receipt["supervision_status"] = "observed"
    except Exception:
        receipt["state_validated"] = False
        receipt["auth_classification"] = "source_or_host_blocked"
        receipt["supervision_status"] = "not_checked"
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["state_validated"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
