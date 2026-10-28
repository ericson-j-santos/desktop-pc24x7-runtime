"""Exact approved DEV supervision application through canonical specific Risk3."""
from __future__ import annotations
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE_SHA = "e0c40bccf0d99858a21beab0d62d0f143e969608"
RULES_SHA = "682bba2858e09c161e7d3a477896ba7e326e83bd"
RUNTIME_MAIN = "e0c40bccf0d99858a21beab0d62d0f143e969608"
DIGEST = "e74b89a5c9ca49ca2b6695d13332e81873dd363e770a9a65894e7a76e5e63396"
CORRELATION = "orchestrator-dev-supervision-review"
ACTION = "pc24x7.orchestrator-dev.supervise.e0c40bcc"
SCOPE = "repo://ericson-j-santos/reqsys-engineering-orchestrator/environment/dev/runner/DESKTOP-PDQK954-orchestrator-dev"
AUTHORIZATION_REF = "owner-chat-exact-supervision-plan-e74b89a5-20261028"


def main():
    receipt = {"kind": "authorized-orchestrator-dev-supervision",
               "source_sha": SOURCE_SHA, "plan_sha256": DIGEST,
               "correlation_id": CORRELATION, "registered_runner_id": 21,
               "registration_performed": False, "authorization_entry_removed": False,
               "additional_cost_authorized_brl": 0, "rdc_used": False,
               "apply_invoked": False}
    entry = gateway = setter = config_path = deploy = None
    try:
        if os.environ.get("EXACT_PLAN_APPROVAL") != DIGEST:
            raise ValueError("administrative_approval_required")
        if not re.fullmatch(r"[0-9a-f]{64}", DIGEST):
            raise ValueError("approved_digest_not_bound")
        source = Path(os.environ["APPROVED_SOURCE_ROOT"]).resolve()
        source.relative_to(Path(r"C:\dev\chatgpt-workers").resolve())
        rules = Path(os.environ["CANONICAL_RULES_ROOT"]).resolve()
        observed = subprocess.run(["git", "-C", str(rules), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=15, check=False)
        if observed.returncode != 0 or observed.stdout.strip() != RULES_SHA:
            raise ValueError("rules_checkout_changed")
        sys.path.insert(0, str(source / "scripts"))
        deploy = importlib.import_module("orchestrator_dev_supervision_deploy")
        if Path(deploy.__file__).resolve() != source / "scripts" / "orchestrator_dev_supervision_deploy.py":
            raise ValueError("deploy_import_path_invalid")
        deploy.source_guard(SOURCE_SHA)
        token = deploy.bootstrap.local_git_owner_token()
        prefix = "/repos/ericson-j-santos/desktop-pc24x7-runtime"
        pr = deploy.bootstrap.api_json(prefix + "/pulls/115", token=token)
        main = deploy.bootstrap.api_json(prefix + "/branches/main", token=token)
        runs = deploy.bootstrap.api_json(prefix + "/actions/workflows/ci.yml/runs?head_sha=" + SOURCE_SHA + "&event=push&per_page=30", token=token)
        deploy.scanner_guard(token)
        token = ""
        if (pr.get("merged") is not True
            or pr.get("head", {}).get("sha") != "674c0d9e89b7b64de643ae1ea1e9761aa482df40"
            or pr.get("merge_commit_sha") != SOURCE_SHA
            or main.get("commit", {}).get("sha") != RUNTIME_MAIN
            or not any(run.get("head_sha") == SOURCE_SHA and run.get("event") == "push"
                       and run.get("run_attempt") == 1 and run.get("status") == "completed"
                       and run.get("conclusion") == "success" for run in runs.get("workflow_runs", []))):
            raise ValueError("approved_source_or_ci_changed")
        plan = deploy.build_plan(SOURCE_SHA, CORRELATION)
        if plan.get("plan_sha256") != DIGEST:
            raise ValueError("approved_plan_changed")
        sys.path.insert(0, str(rules / "scripts"))
        gateway = importlib.import_module("owner_risk3_gateway")
        setter = importlib.import_module("set_owner_risk3_action")
        for module in (gateway, setter):
            Path(module.__file__).resolve().relative_to(rules)
        config_path = gateway.default_config_path()
        config = gateway.load_local_config(config_path)
        if ACTION in config.get("actions", {}):
            raise ValueError("specific_authorization_already_exists")
        authorized = setter.authorize(
            config_path=config_path, action_id=ACTION, scope=SCOPE, environment="dev",
            repo_root=source, expected_head=SOURCE_SHA,
            script=Path("scripts/orchestrator_dev_supervision_deploy.py"),
            args=["apply", "--source-sha", SOURCE_SHA, "--correlation-id", CORRELATION,
                  "--expected-plan-sha256", DIGEST, "--confirm", deploy.CONFIRM],
            expires_minutes=15, authorization_ref=AUTHORIZATION_REF, confirm=setter.CONFIRM)
        entry = gateway.load_local_config(config_path)["actions"][ACTION]
        receipt["risk3_authorization"] = {key: authorized[key] for key in (
            "status", "action_id", "environment", "git_head", "script_sha256",
            "expires_at", "broad_development_mode_changed")}
        receipt["apply_invoked"] = True
        gateway.execute_action(config_path=config_path, action_id=ACTION, scope=SCOPE,
                               cwd=source, timeout=840, correlation_id=CORRELATION)
        receipt["risk3_execution_success"] = True
        receipt["independent_local_readback"] = deploy.readback(SOURCE_SHA, DIGEST)
        receipt.update(ok=True, state="SUPERVISION_ACTIVE_SCANNER_PICKUP_PENDING")
    except Exception as error:
        state = str(error) if isinstance(error, ValueError) else getattr(error, "state", "")
        if not isinstance(state, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,100}", state):
            state = "supervision_application_blocked"
        receipt.update(ok=False, state=state, automatic_retry_performed=False,
                       partial_effects_preserved=True)
        if deploy is not None and receipt["apply_invoked"]:
            try:
                partial = deploy.read_json(deploy.receipt_path(DIGEST))
                receipt["application_receipt"] = partial
            except Exception:
                receipt["failure_readback_status"] = "unavailable"
    finally:
        if entry is not None and config_path is not None:
            try:
                config = gateway.load_local_config(config_path)
                if config.get("actions", {}).get(ACTION) != entry:
                    raise ValueError("authorization_entry_changed")
                del config["actions"][ACTION]
                setter._atomic_write(config_path, config)
                receipt["authorization_entry_removed"] = ACTION not in gateway.load_local_config(config_path).get("actions", {})
            except Exception:
                receipt.update(ok=False, authorization_cleanup_blocked=True)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True and receipt["authorization_entry_removed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
