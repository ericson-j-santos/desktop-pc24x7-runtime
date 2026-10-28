#!/usr/bin/env python3
"""Apply the owner's exact DEV registration approval through canonical Risk 3."""
from __future__ import annotations
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE_SHA = "2232022f310970df54299263f0ea93f48ee2a56a"
RULES_SHA = "25a72d6220d8432c92dfbe6e783aa64dc3891330"
DIGEST = "8f22292df61738635cd4eea583e142999816e8a1dedf862feeb7b60aef9a262f"
CORRELATION = "orchestrator-dev-registration-review-2232022f"
ACTION = "pc24x7.orchestrator-dev.register.2232022f"
SCOPE = "repo://ericson-j-santos/reqsys-engineering-orchestrator/environment/dev/runner/DESKTOP-PDQK954-orchestrator-dev"
AUTHORIZATION_REF = "owner-chat-Autorizo-plan-8f22292d-20261028"


def require_approved_plan(plan: dict) -> None:
    if (plan.get("source_sha") != SOURCE_SHA or plan.get("plan_sha256") != DIGEST
        or plan.get("correlation_id") != CORRELATION or plan.get("ok") is not True
        or plan.get("profile", {}).get("host") != "DESKTOP-PDQK954"
        or plan.get("profile", {}).get("repository") != "ericson-j-santos/reqsys-engineering-orchestrator"
        or plan.get("profile", {}).get("runner_name") != "DESKTOP-PDQK954-orchestrator-dev"
        or plan.get("package", {}).get("version") != "2.338.2"
        or plan.get("listener_start_planned") is not False
        or plan.get("watchdog_change_planned") is not False
        or plan.get("windows_task_change_planned") is not False
        or plan.get("runtime_runner_change_planned") is not False
        or plan.get("additional_cost_authorized_brl") != 0):
        raise ValueError("approved_plan_changed")


def application_args() -> list[str]:
    return ["--confirm", "REGISTER-ORCHESTRATOR-DEV-RUNNER", "--source-sha", SOURCE_SHA,
            "--target", "orchestrator-dev", "--apply", "--correlation-id", CORRELATION,
            "--expected-plan-sha256", DIGEST]


def main() -> int:
    receipt = {"kind": "authorized-orchestrator-dev-registration", "source_sha": SOURCE_SHA,
               "plan_sha256": DIGEST, "registration_performed": False,
               "runner_started": False, "watchdog_changed": False,
               "windows_task_changed": False, "additional_cost_authorized_brl": 0,
               "credential_logged": False, "authorization_entry_removed": False}
    action_entry = None
    config_path = None
    gateway = setter = None
    try:
        source = Path(os.environ["APPROVED_SOURCE_ROOT"]).resolve()
        source.relative_to(Path(r"C:\dev\chatgpt-workers").resolve())
        rules = Path(os.environ["CANONICAL_RULES_ROOT"]).resolve()
        current_rules = subprocess.run(["git", "-C", str(rules), "rev-parse", "HEAD"],
                                       capture_output=True, text=True, timeout=15, check=False)
        if current_rules.returncode != 0 or current_rules.stdout.strip() != RULES_SHA:
            raise ValueError("canonical_rules_changed")
        sys.path.insert(0, str(source / "scripts"))
        bootstrap = importlib.import_module("bootstrap_dedicated_runtime_runner")
        preflight = importlib.import_module("orchestrator_dev_runner_preflight")
        for module in (bootstrap, preflight, bootstrap.watchdog):
            Path(module.__file__).resolve().relative_to(source)
        preflight.require_source(SOURCE_SHA)
        if bootstrap.validate_host().casefold() != "desktop-pdqk954":
            raise ValueError("host_mismatch")
        token = bootstrap.local_git_owner_token()
        repository = "/repos/ericson-j-santos/desktop-pc24x7-runtime"
        pr = bootstrap.api_json(repository + "/pulls/113", token=token)
        main = bootstrap.api_json(repository + "/branches/main", token=token)
        merged = bootstrap.api_json(repository + "/git/commits/c1f224b79a26fe927686e69523f3a4f7cc37ba81", token=token)
        source_commit = bootstrap.api_json(repository + "/git/commits/" + SOURCE_SHA, token=token)
        current_rules = bootstrap.api_json("/repos/ericson-j-santos/chatgpt-operational-rules/branches/main", token=token)
        token = ""
        if (pr.get("merged") is not True or pr.get("head", {}).get("sha") != SOURCE_SHA
            or pr.get("merge_commit_sha") != "c1f224b79a26fe927686e69523f3a4f7cc37ba81"
            or main.get("commit", {}).get("sha") != "c1f224b79a26fe927686e69523f3a4f7cc37ba81"
            or merged.get("tree", {}).get("sha") != source_commit.get("tree", {}).get("sha")
            or source_commit.get("tree", {}).get("sha") != "9c31d4309c27446e32ae39d181220ec76e08ba52"
            or current_rules.get("commit", {}).get("sha") != RULES_SHA):
            raise ValueError("approved_source_or_rules_changed")
        receipt.update(main_sha="c1f224b79a26fe927686e69523f3a4f7cc37ba81", merged_tree_equivalent=True)
        plan = bootstrap.orchestrator_dev_plan(source_sha=SOURCE_SHA, correlation_id=CORRELATION)
        require_approved_plan(plan)
        primary_metadata = Path(os.environ["LOCALAPPDATA"]) / "DesktopPC24x7" / "GitHubRunner" / ".runner"
        preflight.checked_path(primary_metadata, directory=False)
        before = primary_metadata.read_bytes()
        if len(before) > 65536:
            raise ValueError("runtime_metadata_invalid")
        primary_hash = hashlib.sha256(before).hexdigest()
        sys.path.insert(0, str(rules / "scripts"))
        gateway = importlib.import_module("owner_risk3_gateway")
        setter = importlib.import_module("set_owner_risk3_action")
        initializer = importlib.import_module("set_owner_risk3_development_mode")
        for module in (gateway, setter, initializer):
            Path(module.__file__).resolve().relative_to(rules)
        config_path = gateway.default_config_path()
        if not config_path.exists():
            # Initialize only the canonical empty policy; never enable broad DEV mode.
            initializer._atomic_write(config_path, initializer._load_or_initialize(config_path))
            receipt["empty_risk3_policy_initialized"] = True
        config = gateway.load_local_config(config_path)
        if ACTION in config.get("actions", {}):
            raise ValueError("specific_authorization_already_exists")
        authorized = setter.authorize(
            config_path=config_path, action_id=ACTION, scope=SCOPE, environment="dev",
            repo_root=source, expected_head=SOURCE_SHA,
            script=Path("scripts/bootstrap_dedicated_runtime_runner.py"), args=application_args(),
            expires_minutes=15, authorization_ref=AUTHORIZATION_REF,
            confirm=setter.CONFIRM,
        )
        action_entry = gateway.load_local_config(config_path)["actions"][ACTION]
        receipt["risk3_authorization"] = {key: authorized[key] for key in (
            "status", "action_id", "environment", "git_head", "script_sha256",
            "expires_at", "broad_development_mode_changed")}
        receipt["apply_invoked"] = True
        receipt["registration_performed"] = None
        gateway.execute_action(
            config_path=config_path, action_id=ACTION, scope=SCOPE, cwd=source,
            timeout=600, correlation_id="authorized-orchestrator-registration-2232022f",
        )
        receipt["risk3_execution_success"] = True
        readback = preflight.preflight(expected_sha=SOURCE_SHA, correlation_id=CORRELATION, local_auth_only=True)
        runner_id = readback.get("observed_runner_id")
        if readback.get("registration_required") is not False or type(runner_id) is not int or runner_id <= 0:
            raise ValueError("registration_readback_failed")
        home = Path(readback["runner_home"])
        remote = preflight.registry_snapshot(local_auth_only=True)
        if not isinstance(remote, dict) or remote.get("id") != runner_id:
            raise ValueError("registry_readback_changed")
        receipt.update(registration_performed=plan["registration_required"],
                       registered_runner_id=runner_id, registered_runner_name=remote.get("name"),
                       remote_status=remote.get("status"), remote_busy=remote.get("busy"),
                       local_remote_binding_validated=True)
        receipt["binary_version"] = bootstrap._orchestrator_version_probe(home)
        receipt["runtime_metadata_unchanged"] = (
            hashlib.sha256(primary_metadata.read_bytes()).hexdigest() == primary_hash)
        if not receipt["runtime_metadata_unchanged"]:
            raise ValueError("existing_runtime_metadata_changed")
        matches = unresolved = 0
        expected = os.path.normcase(str((home / "bin" / "Runner.Listener.exe").resolve()))
        for pid in bootstrap.watchdog._runner_process_ids():
            executable = bootstrap.watchdog._process_executable_path(pid)
            if executable is None:
                unresolved += 1
            elif os.path.normcase(str(executable)) == expected:
                matches += 1
        receipt.update(new_listener_matching_processes=matches, unresolved_listener_processes=unresolved)
        if matches != 0:
            raise ValueError("unexpected_new_listener")
        receipt.update(ok=True, state="RUNNER_REGISTERED_ACTIVATION_PENDING")
    except Exception as error:
        state = getattr(error, "state", "")
        if not state and isinstance(error, ValueError):
            state = str(error)
        if not isinstance(state, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,100}", state):
            state = "authorized_registration_blocked"
        receipt.update(ok=False, state=state)
        if gateway is not None and isinstance(error, gateway.Risk3Error):
            receipt["risk3_block_reason"] = str(error)[:200]
        receipt["automatic_retry_performed"] = False
        if receipt.get("apply_invoked"):
            try:
                observed = preflight.registry_snapshot(local_auth_only=True)
                receipt["observed_runner_id_after_failure"] = observed.get("id") if isinstance(observed, dict) else None
                receipt["partial_home_present"] = preflight.runner_home().is_dir()
                receipt["partial_installation_preserved"] = True
            except Exception:
                receipt["failure_readback_status"] = "unavailable"
    finally:
        if action_entry is not None and config_path is not None and gateway is not None and setter is not None:
            try:
                config = gateway.load_local_config(config_path)
                if config.get("actions", {}).get(ACTION) != action_entry:
                    raise ValueError("authorization_entry_changed")
                del config["actions"][ACTION]
                setter._atomic_write(config_path, config)
                receipt["authorization_entry_removed"] = ACTION not in gateway.load_local_config(config_path).get("actions", {})
            except Exception:
                receipt["authorization_cleanup_blocked"] = True
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True and receipt.get("authorization_entry_removed") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
