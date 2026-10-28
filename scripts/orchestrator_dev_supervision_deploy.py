#!/usr/bin/env python3
"""Closed plan/apply/readback for the existing Desktop watchdog and runner ID21."""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import bootstrap_dedicated_runtime_runner as bootstrap
import desktop_control_plane_watchdog as watchdog
import orchestrator_dev_runner_preflight as preflight

ORCHESTRATOR = "ericson-j-santos/reqsys-engineering-orchestrator"
SCANNER_PR = 64
SCANNER_HEAD = "2b7a943408eb3adce64d58637d4c9107213300a4"
SCANNER_TREE = "95d0b8dc9339cf4a45faf40651508343706c0466"
RULES_SHA = "682bba2858e09c161e7d3a477896ba7e326e83bd"
TASK_NAME = r"\Automation\DesktopPc24x7RuntimeWatchdog"
CONFIRM = "ACTIVATE-ORCHESTRATOR-DEV-SUPERVISION"
SOURCE_FILES = ("desktop_control_plane_watchdog.py", "pc24x7_host_policy.py",
                "pc24x7_rdc_recovery.py", "desktop_control_plane_watchdog_uac_launcher.py")
NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
MUTABLE_FILES = {".runner", ".credentials", ".credentials_rsaparams", ".env", ".path",
                 ".service", ".proxy", ".proxycredentials", ".proxybypass"}
MUTABLE_DIRS = {"_diag", "_work"}


class Blocked(RuntimeError):
    pass


def require(condition, state):
    if not condition:
        raise Blocked(state)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def file_hash(path):
    path = Path(path)
    preflight.checked_path(path, directory=False)
    require(path.stat().st_nlink == 1, "file_hardlink_rejected")
    return bootstrap.sha256_file(path)


def fixed_root():
    root = watchdog.default_runtime_root()
    preflight.checked_path(root, directory=True)
    return root


def identity():
    cp = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                        capture_output=True, timeout=15, check=False)
    match = re.search(rb"S-1-[0-9-]+", cp.stdout)
    require(cp.returncode == 0 and match, "process_sid_unavailable")
    return match.group().decode("ascii")


def task_file_error():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel.GetFileAttributesW.restype = wintypes.DWORD
    ctypes.set_last_error(0)
    value = kernel.GetFileAttributesW(str(watchdog._task_file_path()))
    return ctypes.get_last_error() if value == 0xFFFFFFFF else 0


def task_xml(python, launcher, sid):
    require(bool(re.fullmatch(r"S-1-[0-9-]+", sid)), "task_sid_invalid")
    ET.register_namespace("", NS)
    def add(parent, name, value=None, **attributes):
        child = ET.SubElement(parent, "{" + NS + "}" + name, attributes)
        if value is not None:
            child.text = value
        return child
    root = ET.Element("{" + NS + "}Task", {"version": "1.4"})
    add(add(root, "RegistrationInfo"), "URI", TASK_NAME)
    triggers = add(root, "Triggers")
    add(add(triggers, "BootTrigger"), "Enabled", "true")
    timer = add(triggers, "TimeTrigger")
    repetition = add(timer, "Repetition")
    add(repetition, "Interval", "PT1M")
    add(repetition, "StopAtDurationEnd", "false")
    add(timer, "StartBoundary", "2026-10-28T00:00:00Z")
    add(timer, "Enabled", "true")
    principal = add(add(root, "Principals"), "Principal", id="Author")
    add(principal, "UserId", sid)
    add(principal, "LogonType", "S4U")
    add(principal, "RunLevel", "LeastPrivilege")
    settings = add(root, "Settings")
    for key, value in (("MultipleInstancesPolicy", "IgnoreNew"),
                       ("DisallowStartIfOnBatteries", "false"), ("StopIfGoingOnBatteries", "false"),
                       ("StartWhenAvailable", "true"), ("RunOnlyIfNetworkAvailable", "false"),
                       ("Enabled", "true"), ("ExecutionTimeLimit", "PT0S")):
        add(settings, key, value)
    restart = add(settings, "RestartOnFailure")
    add(restart, "Interval", "PT1M")
    add(restart, "Count", "999")
    action = add(add(root, "Actions", Context="Author"), "Exec")
    add(action, "Command", str(python))
    add(action, "Arguments", '"' + str(launcher) + '"')
    add(action, "WorkingDirectory", str(launcher.parent))
    return ET.tostring(root, encoding="utf-16", xml_declaration=True)


def validate_task(raw, python, launcher, sid):
    require(len(raw) <= 262144, "task_xml_too_large")
    root = ET.fromstring(raw)
    ns = {"t": NS}
    def value(path):
        return root.findtext(path, default="", namespaces=ns)
    require(value(".//t:URI") == TASK_NAME
            and value(".//t:Principal/t:UserId") == sid
            and value(".//t:Principal/t:LogonType") == "S4U"
            and value(".//t:Principal/t:RunLevel") == "LeastPrivilege"
            and value(".//t:Actions/t:Exec/t:Command").casefold() == str(python).casefold()
            and value(".//t:Actions/t:Exec/t:Arguments") == '"' + str(launcher) + '"'
            and value(".//t:Actions/t:Exec/t:WorkingDirectory").casefold() == str(launcher.parent).casefold()
            and root.find(".//t:BootTrigger", ns) is not None
            and value(".//t:TimeTrigger/t:Repetition/t:Interval") == "PT1M"
            and value(".//t:MultipleInstancesPolicy") == "IgnoreNew",
            "task_binding_rejected")
    return {"principal_sid_matches_process": True, "s4u": True,
            "boot_trigger": True, "minute_recovery_trigger": True}


def query_task():
    return subprocess.run(["schtasks.exe", "/Query", "/TN", TASK_NAME, "/XML"],
                          capture_output=True, timeout=20, check=False)


def read_json(path):
    preflight.checked_path(path, directory=False)
    raw = path.read_bytes()
    require(len(raw) <= 262144, "json_too_large")
    data = json.loads(raw)
    require(isinstance(data, dict), "json_invalid")
    return data


def source_guard(sha):
    require(bool(preflight.SHA_RE.fullmatch(sha)), "source_sha_invalid")
    preflight.require_source(sha)
    require(Path(__file__).resolve() == ROOT / "scripts" / "orchestrator_dev_supervision_deploy.py", "deploy_source_path_invalid")
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "--",
                              "scripts/orchestrator_dev_supervision_deploy.py"],
                             capture_output=True, timeout=15, check=False)
    require(tracked.returncode == 0, "deploy_source_untracked")
    require(bootstrap.validate_host().casefold() == "desktop-pdqk954", "host_mismatch")
    require(bool(ctypes.windll.shell32.IsUserAnAdmin()), "elevated_executor_required")


def scanner_guard(token):
    prefix = "/repos/" + ORCHESTRATOR
    main = bootstrap.api_json(prefix + "/branches/main", token=token)
    pr = bootstrap.api_json(prefix + "/pulls/" + str(SCANNER_PR), token=token)
    rules = bootstrap.api_json("/repos/ericson-j-santos/chatgpt-operational-rules/branches/main", token=token)
    merged = pr.get("merge_commit_sha")
    require(pr.get("merged") is True and pr.get("head", {}).get("sha") == SCANNER_HEAD
            and isinstance(merged, str) and bool(preflight.SHA_RE.fullmatch(merged))
            and main.get("commit", {}).get("sha") == merged
            and rules.get("commit", {}).get("sha") == RULES_SHA, "scanner_source_or_rules_moved")
    commit = bootstrap.api_json(prefix + "/git/commits/" + merged, token=token)
    require(commit.get("tree", {}).get("sha") == SCANNER_TREE, "scanner_tree_mismatch")
    return merged


def registration():
    remote = preflight.registry_snapshot(local_auth_only=True)
    require(isinstance(remote, dict) and remote.get("id") == 21
            and remote.get("name") == "DESKTOP-PDQK954-orchestrator-dev", "runner_registry_changed")
    preflight.require_local_binding(preflight.runner_home(), remote)
    return remote


def verify_package(home):
    bootstrap._orchestrator_package_policy()
    with tempfile.TemporaryDirectory(prefix="activation-verify-", dir=home.parent) as temporary:
        temporary_root = Path(temporary).resolve()
        temporary_root.relative_to(home.parent.resolve())
        package = bootstrap._orchestrator_download_package(temporary_root)
        manifest = bootstrap._orchestrator_binary_manifest(package)
        for relative, expected in manifest.items():
            path = home / relative.rstrip("/")
            preflight.checked_path(path, directory=expected == "directory")
            if expected != "directory":
                require(file_hash(path) == expected, "installed_payload_mismatch")
        def walk(directory):
            preflight.checked_path(directory, directory=True)
            with os.scandir(directory) as stream:
                paths = [Path(entry.path) for entry in stream]
            for path in paths:
                preflight.checked_path(path, directory=path.is_dir())
                yield path
                if path.is_dir():
                    yield from walk(path)
        for path in walk(home):
            relative = path.relative_to(home).as_posix()
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, "st_file_attributes", 0) & 0x400, "installed_link_rejected")
            if relative in manifest or relative + "/" in manifest:
                continue
            top = path.relative_to(home).parts[0]
            require(top in MUTABLE_DIRS or (len(path.relative_to(home).parts) == 1
                    and top in MUTABLE_FILES and stat.S_ISREG(info.st_mode)),
                    "unexpected_installed_path")
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, "installed_hardlink_rejected")
        return digest(manifest)


def build_plan(sha, correlation):
    source_guard(sha)
    require(bool(preflight.CORRELATION_RE.fullmatch(correlation)), "correlation_invalid")
    token = bootstrap.local_git_owner_token()
    scanner_main = scanner_guard(token)
    token = ""
    preflight.require_orchestrator()
    remote = registration()
    require(remote.get("status") == "offline" and remote.get("busy") is False, "runner_not_idle_offline")
    home = preflight.runner_home()
    snapshot = watchdog.runner_process_snapshot(home)
    require(not snapshot["matching_pids"] and not snapshot["unresolved_pids"], "runner_process_identity_unverifiable")
    root = fixed_root()
    installed = watchdog.load_installed_metadata(root / "metadata.json")
    primary = Path(os.environ["LOCALAPPDATA"]) / "DesktopPC24x7" / "GitHubRunner"
    require(Path(installed["metadata"]["runner_home"]).resolve() == primary.resolve(),
            "primary_runner_home_changed")
    snapshot = query_task()
    require(snapshot.returncode != 0 and task_file_error() in (2, 3), "task_not_confirmed_absent")
    lock = watchdog._acquire_watch_lock(root)
    lock.close()
    sid = identity()
    hashes = {name: file_hash(ROOT / "scripts" / name) for name in SOURCE_FILES}
    manifest = verify_package(home)
    plan = {
        "schema_version": 1, "kind": "orchestrator-dev-supervised-activation-plan",
        "source_sha": sha, "rules_sha": RULES_SHA, "correlation_id": correlation,
        "host": "DESKTOP-PDQK954", "runner_id": 21, "scanner_main_sha": scanner_main,
        "runner_home": str(home), "watchdog_root": str(root),
        "old_source_sha": installed["source_sha"], "source_files": hashes,
        "old_metadata_sha256": file_hash(root / "metadata.json"),
        "old_launcher_sha256": file_hash(root / "run.py"),
        "primary_runner_metadata_sha256": file_hash(primary / ".runner"),
        "python_executable": str(installed["python_executable"]),
        "python_sha256": file_hash(installed["python_executable"]),
        "task_name": TASK_NAME, "task_creation_only_if_absent": True,
        "task_xml_sha256": hashlib.sha256(task_xml(installed["python_executable"], root / "run.py", sid)).hexdigest(),
        "principal_sid_sha256": hashlib.sha256(sid.encode()).hexdigest(),
        "official_package_manifest_sha256": manifest, "package_version": "2.338.2",
        "additional_runner_profiles": ["orchestrator-dev"], "rdc_recovery_enabled": False,
        "administrative_effects": [
            "backup_existing_watchdog_metadata_and_launcher",
            "stage_verified_source_release_preserving_primary_runner_home",
            "create_only_the_absent_canonical_s4u_task_with_same_process_sid",
            "pause_only_pr_health_scan_and_cancel_only_unpicked_up_scanner_runs",
            "start_existing_watchdog_with_closed_additional_runner_profile",
            "stop_only_idle_new_listener_and_prove_supervisor_recovery",
            "restore_scanner_workflow",
        ],
        "reversal": [
            "disable_only_the_new_canonical_task_after_idle_check",
            "stop_only_the_new_profile_listener_and_this_watchdog_after_identity_readback",
            "restore_backup_metadata_and_launcher_with_digest_readback",
            "preserve_both_runner_registrations_and_payloads",
            "restore_pr_health_scan_to_prior_active_state",
        ],
        "pickup_followup_required": True,
        "new_supervisor_manager_created": False, "host_reboot_planned": False,
        "additional_cost_authorized_brl": 0,
    }
    return {**plan, "plan_sha256": digest(plan), "state": "ACTIVATION_PLAN_READY_EXECUTION_PENDING",
            "configuration_read_only": True, "temporary_package_verification": True}


def request_control(token, path, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request("https://api.github.com" + path, data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            require(response.status in (202, 204), "control_response_invalid")
    except Exception:
        # Uncertain POST outcomes are reconciled by the caller, never retried here.
        raise Blocked("control_outcome_unconfirmed") from None


def workflow_state(token):
    return bootstrap.api_json("/repos/" + ORCHESTRATOR + "/actions/workflows/pr-health-scan.yml", token=token)


def pause_scanner(token):
    workflow = workflow_state(token)
    require(workflow.get("state") == "active", "scanner_not_active_before_maintenance")
    try:
        request_control(token, "/repos/" + ORCHESTRATOR + "/actions/workflows/pr-health-scan.yml/disable")
    except Blocked:
        pass
    require(workflow_state(token).get("state") == "disabled_manually", "scanner_pause_unconfirmed")


def restore_scanner(token):
    current = workflow_state(token).get("state")
    if current != "active":
        require(current == "disabled_manually", "scanner_restore_state_changed")
        try:
            request_control(token, "/repos/" + ORCHESTRATOR + "/actions/workflows/pr-health-scan.yml/enable")
        except Blocked:
            pass
    require(workflow_state(token).get("state") == "active", "scanner_restore_unconfirmed")


def drain_scanner(token):
    cancelled = []
    for state in ("queued", "in_progress", "waiting", "pending", "requested"):
        listing = bootstrap.api_json("/repos/" + ORCHESTRATOR + "/actions/workflows/pr-health-scan.yml/runs?status=" + state + "&per_page=100", token=token)
        runs = listing.get("workflow_runs")
        require(isinstance(runs, list) and listing.get("total_count") == len(runs), "scanner_active_listing_incomplete")
        for run in runs:
            identifier = run.get("id")
            if identifier in cancelled:
                continue
            require(type(identifier) is int and identifier > 0, "scanner_run_id_invalid")
            jobs = bootstrap.api_json("/repos/" + ORCHESTRATOR + "/actions/runs/" + str(identifier) + "/jobs?per_page=100", token=token)
            require(jobs.get("total_count") == len(jobs.get("jobs", [])), "scanner_jobs_incomplete")
            if any(job.get("runner_id") or job.get("status") == "in_progress" for job in jobs["jobs"]):
                continue
            try:
                request_control(token, "/repos/" + ORCHESTRATOR + "/actions/runs/" + str(identifier) + "/cancel")
            except Blocked:
                pass
            for _ in range(12):
                check = bootstrap.api_json("/repos/" + ORCHESTRATOR + "/actions/runs/" + str(identifier), token=token)
                if check.get("status") == "completed":
                    break
                time.sleep(5)
            require(check.get("status") == "completed" and check.get("conclusion") == "cancelled",
                    "scanner_queue_cancellation_unconfirmed")
            cancelled.append(identifier)
    for _ in range(60):
        if registration().get("busy") is False:
            return sorted(set(cancelled))
        time.sleep(5)
    raise Blocked("runner_still_busy")


def live_state(sha):
    root = fixed_root()
    state = read_json(root / "state.json")
    stamp = datetime.fromisoformat(str(state["generated_at"]).replace("Z", "+00:00"))
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    additional = state.get("additional_runners", {}).get("orchestrator-dev", {})
    require(state.get("source_sha") == sha and 0 <= age <= 90 and state.get("ok") is True
            and state.get("primary_runner_recovery_ok") is True
            and state.get("rdc_recovery_enabled") is False
            and additional.get("runner_id") == 21
            and additional.get("status") in ("recovered", "process_running"),
            "supervisor_state_not_current_healthy")
    return {"fresh_90s": True, "source_sha": sha, "primary_runner_ok": True,
            "additional_runner_ok": True, "rdc_recovery_enabled": False}


def wait_online(sha, timeout=180, previous_pid=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = live_state(sha)
            remote = registration()
            snapshot = watchdog.runner_process_snapshot(preflight.runner_home())
            pids = snapshot["matching_pids"]
            if remote.get("status") == "online" and len(pids) == 1 and (
                    previous_pid is None or pids[0] != previous_pid):
                return {**state, "runner_online": True, "listener_pid": pids[0]}
        except Exception:
            pass
        time.sleep(5)
    raise Blocked("supervisor_online_readback_expired")


def stage_release(plan):
    root = fixed_root()
    backup = root / "backups" / "orchestrator-dev" / plan["plan_sha256"]
    preflight.checked_path(backup, directory=True, allow_missing_tail=True)
    backup.mkdir(parents=True, exist_ok=True)
    for name, expected in (("metadata.json", plan["old_metadata_sha256"]), ("run.py", plan["old_launcher_sha256"])):
        source = root / name
        require(file_hash(source) == expected, "legacy_installation_changed")
        target = backup / name
        if target.exists():
            require(file_hash(target) == expected, "backup_collision")
        else:
            target.write_bytes(source.read_bytes())
            require(file_hash(target) == expected, "backup_readback_failed")
    manifest_path = backup / "manifest.json"
    manifest = {"plan_sha256": plan["plan_sha256"], "source_sha": plan["source_sha"],
                "metadata_sha256": plan["old_metadata_sha256"], "launcher_sha256": plan["old_launcher_sha256"]}
    if manifest_path.exists():
        require(read_json(manifest_path) == manifest, "backup_manifest_collision")
    else:
        watchdog.atomic_json(manifest_path, manifest)
    release = root / "releases" / plan["source_sha"]
    preflight.checked_path(release, directory=True, allow_missing_tail=True)
    if not release.exists():
        release.mkdir(parents=True)
        (release / "scripts").mkdir()
    preflight.checked_path(release / "scripts", directory=True)
    for name, expected in plan["source_files"].items():
        source = ROOT / "scripts" / name
        require(file_hash(source) == expected, "source_file_changed")
        target = release / "scripts" / name
        if target.exists():
            require(file_hash(target) == expected, "release_collision")
        else:
            target.write_bytes(source.read_bytes())
            require(file_hash(target) == expected, "release_readback_failed")
    metadata = read_json(root / "metadata.json")
    metadata.update(source_sha=plan["source_sha"], release_root=str(release),
                    additional_runner_profiles=["orchestrator-dev"], rdc_recovery_enabled=False)
    watchdog.atomic_bytes(root / "run.py", watchdog.launcher_bytes())
    watchdog.atomic_json(root / "metadata.json", metadata)
    return backup


def create_task(plan):
    require(query_task().returncode != 0 and task_file_error() in (2, 3), "task_appeared_before_create")
    sid = identity()
    require(hashlib.sha256(sid.encode()).hexdigest() == plan["principal_sid_sha256"], "process_identity_changed")
    xml = task_xml(Path(plan["python_executable"]), fixed_root() / "run.py", sid)
    require(hashlib.sha256(xml).hexdigest() == plan["task_xml_sha256"], "task_contract_changed")
    with tempfile.TemporaryDirectory(prefix="task-registration-", dir=fixed_root()) as temporary:
        target = Path(temporary).resolve()
        target.relative_to(fixed_root().resolve())
        path = target / "task.xml"
        path.write_bytes(xml)
        created = subprocess.run(["schtasks.exe", "/Create", "/TN", TASK_NAME, "/XML", str(path)],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    require(created.returncode == 0, "task_create_failed")
    query = query_task()
    require(query.returncode == 0, "task_create_readback_failed")
    return validate_task(query.stdout, Path(plan["python_executable"]), fixed_root() / "run.py", sid)


def receipt_path(plan_digest):
    require(bool(re.fullmatch(r"[0-9a-f]{64}", plan_digest)), "plan_digest_invalid")
    return fixed_root() / "evidence" / ("orchestrator-dev-activation-" + plan_digest + ".json")


def apply(sha, correlation, expected_digest, confirmation):
    require(confirmation == CONFIRM, "confirmation_invalid")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", expected_digest or "")), "plan_digest_invalid")
    source_guard(sha)
    existing_path = receipt_path(expected_digest)
    if existing_path.exists():
        existing = read_json(existing_path)
        require(existing.get("source_sha") == sha and existing.get("plan_sha256") == expected_digest
                and existing.get("ok") is True, "activation_receipt_conflict")
        live_state(sha)
        return {**existing, "replayed": True}
    plan = build_plan(sha, correlation)
    require(plan["plan_sha256"] == expected_digest, "activation_plan_changed")
    token = bootstrap.local_git_owner_token()
    scanner_guard(token)
    restore_required = False
    receipt = {"kind": "orchestrator-dev-supervised-activation", "source_sha": sha,
               "plan_sha256": expected_digest, "runner_id": 21, "runner_registered_again": False,
               "host_reboot_performed": False, "additional_cost_authorized_brl": 0,
               "scanner_main_sha": plan["scanner_main_sha"], "rdc_used": False, "replayed": False}
    try:
        require(workflow_state(token).get("state") == "active", "scanner_not_active_before_maintenance")
        restore_required = True
        receipt["pause_attempted"] = True
        pause_scanner(token)
        receipt["cancelled_unpicked_scanner_runs"] = drain_scanner(token)
        lock = watchdog._acquire_watch_lock(fixed_root())
        try:
            preflight.require_source(sha)
            require(file_hash(fixed_root() / "metadata.json") == plan["old_metadata_sha256"]
                    and file_hash(fixed_root() / "run.py") == plan["old_launcher_sha256"],
                    "legacy_installation_changed")
            require(registration().get("status") == "offline", "runner_state_changed")
            backup = stage_release(plan)
            receipt["backup_directory_name"] = backup.name
            receipt["installation_staged"] = True
            receipt["task_identity"] = create_task(plan)
        finally:
            lock.close()
        started = subprocess.run(["schtasks.exe", "/Run", "/TN", TASK_NAME],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
        require(started.returncode == 0, "watchdog_task_start_failed")
        receipt["initial_online_proof"] = wait_online(sha)
        require(registration().get("busy") is False, "new_runner_busy_before_recovery_test")
        snapshot = watchdog.runner_process_snapshot(preflight.runner_home())
        require(len(snapshot["matching_pids"]) == 1 and not snapshot["unresolved_pids"], "listener_identity_unverifiable")
        previous = snapshot["matching_pids"][0]
        watchdog.stop_runner(preflight.runner_home())
        receipt["recovery_proof"] = wait_online(sha, timeout=150, previous_pid=previous)
        receipt["controlled_idle_listener_recovery_proven"] = True
        primary = Path(os.environ["LOCALAPPDATA"]) / "DesktopPC24x7" / "GitHubRunner" / ".runner"
        require(file_hash(primary) == plan["primary_runner_metadata_sha256"], "primary_runner_metadata_changed")
        receipt["primary_runner_metadata_unchanged"] = True
        receipt.update(ok=True, state="SUPERVISION_ACTIVE_SCANNER_PICKUP_PENDING",
                       primary_runner_metadata_sha256=plan["primary_runner_metadata_sha256"])
    except Exception as error:
        receipt.update(ok=False, state=safe_state(error), partial_effects_preserved=True,
                       automatic_retry_performed=False)
    finally:
        if restore_required:
            try:
                restore_scanner(token)
                receipt["scanner_workflow_restored"] = True
            except Exception:
                receipt.update(ok=False, state="scanner_restore_unconfirmed",
                               scanner_workflow_restored=False, partial_effects_preserved=True)
        token = ""
        watchdog.atomic_json(existing_path, receipt)
    return receipt


def readback(sha, expected_digest):
    source_guard(sha)
    receipt = read_json(receipt_path(expected_digest))
    require(receipt.get("ok") is True and receipt.get("source_sha") == sha
            and receipt.get("plan_sha256") == expected_digest, "activation_receipt_invalid")
    receipt["live_supervisor"] = live_state(sha)
    remote = registration()
    require(remote.get("status") == "online", "runner_not_online")
    query = query_task()
    require(query.returncode == 0, "task_readback_failed")
    metadata = watchdog.load_installed_metadata(fixed_root() / "metadata.json")
    receipt["live_task_identity"] = validate_task(query.stdout, metadata["python_executable"],
                                                fixed_root() / "run.py", identity())
    primary = Path(os.environ["LOCALAPPDATA"]) / "DesktopPC24x7" / "GitHubRunner" / ".runner"
    require(file_hash(primary) == receipt["primary_runner_metadata_sha256"], "primary_runner_metadata_changed")
    receipt["live_runner_online"] = True
    return receipt


def safe_state(error):
    state = str(error) if isinstance(error, Blocked) else getattr(error, "state", "")
    return state if isinstance(state, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,100}", state) else "supervision_operation_blocked"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "apply", "readback"))
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--correlation-id", default="orchestrator-dev-supervision")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    try:
        if args.mode == "plan":
            result = build_plan(args.source_sha, args.correlation_id)
        elif args.mode == "apply":
            result = apply(args.source_sha, args.correlation_id, args.expected_plan_sha256, args.confirm)
        else:
            result = readback(args.source_sha, args.expected_plan_sha256)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result.get("ok", True) else 2
    except Exception as error:
        state = safe_state(error)
        print(json.dumps({"ok": False, "state": state, "automatic_retry_performed": False,
                          "partial_effects_preserved": True, "runner_registered_again": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
