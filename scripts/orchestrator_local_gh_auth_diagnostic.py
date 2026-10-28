#!/usr/bin/env python3
"""Classify local GitHub CLI auth and existing watchdog identity without secrets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

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
                [str(binary), "auth", "token", "--hostname", "github.com", "--no-refresh"],
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



def probe_same_profile_config() -> dict[str, object]:
    """Check only fixed current-user config locations; never read or print tokens."""
    context: dict[str, object] = {
        "gh_config_dir_set": bool(os.environ.get("GH_CONFIG_DIR")),
        "xdg_config_home_set": bool(os.environ.get("XDG_CONFIG_HOME")),
        "appdata_set": bool(os.environ.get("APPDATA")),
        "appdata_hosts_file_present": None,
        "same_profile_auth": "not_checked",
        "owner_token_present_but_inactive": None,
        "gh_version": None,
    }
    binary = bootstrap.find_gh()
    if binary is None:
        return context
    env = bootstrap.gh_env()
    env["GH_PROMPT_DISABLED"] = "1"
    env["GH_HOST"] = "github.com"
    try:
        version = subprocess.run(
            [str(binary), "--version"], env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=10, check=False,
        )
        match = re.search(r"\bgh version (\d+\.\d+\.\d+)\b", version.stdout)
        if version.returncode == 0 and match:
            context["gh_version"] = match.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    appdata = os.environ.get("APPDATA")
    profile = os.environ.get("USERPROFILE")
    if not appdata or not profile:
        return context
    directory = Path(appdata) / "GitHub CLI"
    try:
        if not directory.is_absolute() or not Path(profile).is_absolute():
            return context
        directory.resolve(strict=False).relative_to(Path(profile).resolve(strict=False))
        context["appdata_hosts_file_present"] = (directory / "hosts.yml").is_file()
    except (OSError, ValueError):
        return context
    candidate_env = dict(env)
    candidate_env.pop("XDG_CONFIG_HOME", None)
    candidate_env["GH_CONFIG_DIR"] = str(directory)
    try:
        token = subprocess.run(
            [str(binary), "auth", "token", "--hostname", "github.com", "--no-refresh"],
            env=candidate_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        context["same_profile_auth"] = "probe_unavailable"
        return context
    if token.returncode != 0:
        try:
            owner_token = subprocess.run(
                [str(binary), "auth", "token", "--hostname", "github.com",
                 "--user", OWNER, "--no-refresh"],
                env=candidate_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            context["same_profile_auth"] = "owner_probe_unavailable"
            return context
        context["owner_token_present_but_inactive"] = owner_token.returncode == 0
        context["same_profile_auth"] = (
            "owner_credential_inactive" if owner_token.returncode == 0
            else "credential_unavailable"
        )
        return context
    try:
        api = subprocess.run(
            [str(binary), "api", "user", "--jq", ".login"],
            env=candidate_env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        context["same_profile_auth"] = "api_unavailable"
        return context
    if api.returncode != 0:
        context["same_profile_auth"] = (
            "authentication_invalid"
            if "http 401" in (api.stderr or "").casefold()
            else "api_failure_unclassified"
        )
    elif api.stdout.strip().casefold() == OWNER.casefold():
        context["same_profile_auth"] = "owner_validated"
    else:
        context["same_profile_auth"] = "account_mismatch"
    return context


def probe_git_credential() -> dict[str, object]:
    """Use the configured Git helper for one fixed repo; keep secrets in memory."""
    report: dict[str, object] = {
        "credential_source": "git_configured_helper",
        "credential_status": "unavailable", "owner_validated": False,
        "registry_status": "not_checked", "runner_count": None,
        "credential_logged": False, "credential_storage_write_requested": False,
        "credential_helper_may_refresh": True,
    }
    env = bootstrap.gh_env()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never"})
    try:
        result = subprocess.run(
            ["git", "-c", "credential.interactive=false", "credential", "fill"],
            input="protocol=https\nhost=github.com\npath=ericson-j-santos/reqsys-engineering-orchestrator.git\nusername=ericson-j-santos\n\n",
            cwd=Path(__file__).resolve().parents[1],
            env=env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return report
    if result.returncode != 0 or len(result.stdout) > 65536:
        return report
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    token = fields.get("password", "")
    if fields.get("host") != "github.com" or not 8 <= len(token) <= 8192:
        return report
    report["credential_status"] = "present"
    def read(path: str) -> dict:
        request = urllib.request.Request(
            "https://api.github.com" + path,
            headers={"Authorization": "Bearer " + token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(262145)
        if len(raw) > 262144:
            raise ValueError("bounded_response")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid_response")
        return value
    try:
        user = read("/user")
    except urllib.error.HTTPError as error:
        report["credential_status"] = "invalid" if error.code == 401 else "api_rejected"
        return report
    except Exception:
        report["credential_status"] = "validation_unavailable"
        return report
    if str(user.get("login") or "").casefold() != OWNER.casefold():
        report["credential_status"] = "account_mismatch"
        return report
    report["owner_validated"] = True
    try:
        registry = read("/repos/ericson-j-santos/reqsys-engineering-orchestrator/actions/runners?per_page=100")
        runners = registry.get("runners")
        total = registry.get("total_count")
        if not isinstance(runners, list) or type(total) is not int or total != len(runners):
            raise ValueError("registry_incomplete")
        report["registry_status"] = "observed"
        report["runner_count"] = total
    except urllib.error.HTTPError as error:
        report["registry_status"] = "permission_denied" if error.code == 403 else "api_rejected"
    except Exception:
        report["registry_status"] = "unavailable"
    return report


def probe_health_supervisor() -> dict[str, object]:
    """Query the installed health supervisor, not the separate runtime watchdog."""
    task_name = r"\Automation\DesktopPc24x7RuntimeHealthSupervisor"
    report: dict[str, object] = {
        "task_kind": "runtime_health_supervisor", "task_query_status": "unavailable",
        "process_sid_matches_task_principal": None, "task_s4u": None,
        "task_boot_trigger": None, "task_action_matches_installed_launcher": None,
        "installed_source_sha": None, "evidence_status": None, "fresh_300s": None,
    }
    try:
        root = Path(os.environ["LOCALAPPDATA"]) / "DesktopPC24x7" / "RuntimeSupervisor"
        preflight.checked_path(root, directory=True)
        for filename in ("install-evidence.json", "evidence.json"):
            path = root / filename
            preflight.checked_path(path, directory=False)
            raw = path.read_bytes()
            if len(raw) > 262144:
                raise ValueError("bounded_file")
            payload = json.loads(raw)
            if filename == "install-evidence.json":
                sha = payload.get("source_sha")
                report["installed_source_sha"] = sha if isinstance(sha, str) and preflight.SHA_RE.fullmatch(sha) else None
            else:
                status = payload.get("status")
                report["evidence_status"] = status if status in ("ok", "degraded", "blocked", "failed") else "other"
                stamp = datetime.fromisoformat(str(payload["timestamp"]).replace("Z", "+00:00")).timestamp()
                age = time.time() - stamp
                report["fresh_300s"] = 0 <= age <= 300
    except Exception:
        pass
    try:
        task = subprocess.run(
            ["schtasks.exe", "/Query", "/TN", task_name, "/XML"],
            capture_output=True, timeout=15, check=False,
        )
        if task.returncode != 0:
            report["task_query_status"] = "query_failed"
            return report
        raw = task.stdout
        if len(raw) > 262144:
            return report
        xml = raw.decode("utf-16" if raw.startswith(b"\xff\xfe") or b"\x00" in raw[:80] else "utf-8-sig")
        definition = ET.fromstring(xml)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        if definition.findtext(".//t:URI", namespaces=ns) != task_name:
            report["task_query_status"] = "identity_mismatch"
            return report
        principal = definition.findtext(".//t:Principal/t:UserId", default="", namespaces=ns)
        report["task_query_status"] = "observed"
        report["task_s4u"] = definition.findtext(".//t:Principal/t:LogonType", namespaces=ns) == "S4U"
        report["task_boot_trigger"] = definition.find(".//t:BootTrigger", ns) is not None
        args = definition.findtext(".//t:Actions/t:Exec/t:Arguments", default="", namespaces=ns)
        report["task_action_matches_installed_launcher"] = (
            args.strip().strip('"').casefold() == str(root / "run-supervisor.py").casefold()
        )
        who = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                             capture_output=True, timeout=10, check=False)
        current = re.search(rb"S-1-[0-9-]+", who.stdout)
        if who.returncode == 0 and current and re.fullmatch(r"S-1-[0-9-]+", principal):
            report["process_sid_matches_task_principal"] = current.group().decode("ascii") == principal
    except Exception:
        report["task_query_status"] = "unavailable"
    return report

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
        "runtime_read_only": True,
        "registration_performed": False,
        "runner_started": False,
        "watchdog_changed": False,
        "auth_classification": "not_checked",
        "gh_located": None,
        "owner_validated": False,
        "gh_config_context": None,
        "git_credential_probe": None,
        "health_supervisor": None,
        "supervision": {key: None for key in IDENTITY_FIELDS},
    }
    try:
        if receipt["source_sha"] is None or receipt["correlation_id"] is None:
            raise ValueError("invalid_request")
        preflight.require_source(args.expected_sha)
        if bootstrap.validate_host().casefold() != receipt["host"].casefold():
            raise ValueError("host_mismatch")
        receipt["state_validated"] = True
        receipt["git_credential_probe"] = probe_git_credential()
        receipt["health_supervisor"] = probe_health_supervisor()
        state, located, owner_validated = diagnose_auth()
        receipt["auth_classification"] = state
        receipt["gh_located"] = located
        receipt["owner_validated"] = owner_validated
        if state == "credential_unavailable":
            receipt["gh_config_context"] = probe_same_profile_config()
            alternate = receipt["gh_config_context"]["same_profile_auth"]
            if alternate == "owner_validated":
                receipt["auth_classification"] = "config_directory_mismatch"
            elif alternate == "owner_credential_inactive":
                receipt["auth_classification"] = "owner_credential_inactive"
            elif alternate in ("account_mismatch", "authentication_invalid"):
                receipt["auth_classification"] = alternate
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
