#!/usr/bin/env python3
"""Upgrade an active Desktop free control plane without replacing its runner or task."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import bootstrap_dedicated_runtime_runner as runner
import desktop_control_plane_watchdog as watchdog
import desktop_control_plane_watchdog_uac_launcher as uac
import repair_desktop_free_control_plane as repair

CONFIRM = "UPGRADE-DESKTOP-FREE-CONTROL-PLANE"
CONTRACT = "desktop-free-control-plane-upgrade-v1"
BACKUP_FILES = ("metadata.json", "run.py", "repair-evidence.json", "uac-result.json")


class UpgradeBlocked(RuntimeError):
    pass


def require_digest(value: str, reason: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise UpgradeBlocked(reason)
    return normalized


def inspect_active_installation(
    source_root: Path,
    *,
    target_sha: str,
    expected_installed_sha: str,
    expected_watchdog_sha256: str,
    expected_uac_sha256: str,
    expected_launcher_sha256: str,
) -> dict[str, Any]:
    target = repair.require_sha(target_sha, "source_sha_invalid")
    previous = repair.require_sha(expected_installed_sha, "expected_installed_sha_invalid")
    expected_watchdog = require_digest(expected_watchdog_sha256, "expected_watchdog_sha256_invalid")
    expected_uac = require_digest(expected_uac_sha256, "expected_uac_sha256_invalid")
    expected_launcher = require_digest(expected_launcher_sha256, "expected_launcher_sha256_invalid")
    host = watchdog.require_windows_desktop()
    if host.casefold() != socket.gethostname().casefold():
        raise UpgradeBlocked("host_identity_changed")
    if host.casefold() != "desktop-rp23ogs":
        raise UpgradeBlocked("lenovo_host_required")

    runtime_root = watchdog.default_runtime_root().resolve()
    metadata_path = runtime_root / "metadata.json"
    # This upgrader intentionally executes from the clean target checkout, not
    # from the currently installed release.  The immutable installed release is
    # still proven below by its metadata path and pinned file digests.
    installation = watchdog.load_installed_metadata(metadata_path)
    metadata = dict(installation["metadata"])
    if repair.require_sha(str(metadata.get("source_sha") or ""), "installed_source_sha_invalid") != previous:
        raise UpgradeBlocked("installed_source_sha_changed")
    if str(metadata.get("host") or "").casefold() != host.casefold():
        raise UpgradeBlocked("installed_metadata_host_mismatch")
    task = watchdog.task_status()
    if not uac.task_headless_ready(task):
        raise UpgradeBlocked("atstartup_s4u_required")
    task_runtime = watchdog.task_runtime_snapshot()
    if task_runtime.get("enabled") is not True:
        raise UpgradeBlocked("watchdog_task_disabled")

    release_root = Path(installation["release_root"])
    installed_watchdog = repair.fixed_release_file(
        release_root, "desktop_control_plane_watchdog.py"
    )
    installed_uac = repair.fixed_release_file(
        release_root, "desktop_control_plane_watchdog_uac_launcher.py"
    )
    launcher = runtime_root / "run.py"
    if not launcher.is_file() or launcher.is_symlink():
        raise UpgradeBlocked("installed_launcher_invalid")
    if repair.sha256_file(installed_watchdog) != expected_watchdog:
        raise UpgradeBlocked("installed_watchdog_digest_changed")
    if repair.sha256_file(installed_uac) != expected_uac:
        raise UpgradeBlocked("installed_uac_digest_changed")
    if repair.sha256_file(launcher) != expected_launcher:
        raise UpgradeBlocked("installed_launcher_digest_changed")

    runner_home_value = str(metadata.get("runner_home") or "").strip()
    if not runner_home_value:
        raise UpgradeBlocked("installed_runner_home_missing")
    runner_home = watchdog.validate_runner_home(Path(runner_home_value))
    process = watchdog.runner_process_snapshot(runner_home)
    pids = process.get("matching_pids") or []
    if len(pids) != 1 or process.get("unresolved_pids"):
        raise UpgradeBlocked("runner_process_identity_unproven")
    profile = repair.configure_runner_contract(host)
    registry = runner.registry_snapshot(None)
    if not repair.registry_ready(registry):
        raise UpgradeBlocked("runner_registry_not_ready")
    if registry.get("name") not in {None, profile.runner_name}:
        raise UpgradeBlocked("runner_registry_name_changed")

    return {
        "source_root": source_root,
        "target_sha": target,
        "previous_sha": previous,
        "runtime_root": runtime_root,
        "metadata_path": metadata_path,
        "metadata": metadata,
        "task": task,
        "task_runtime": task_runtime,
        "runner_home": runner_home,
        "runner_process": process,
        "registry": registry,
        "profile": profile,
        "launcher_sha256": expected_launcher,
    }


def create_backup(context: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    runtime_root = context["runtime_root"]
    backup_id = f"upgrade-{context['previous_sha']}-{context['launcher_sha256'][:16]}"
    destination = runtime_root / "backups" / backup_id
    manifest_path = destination / "manifest.json"
    files = {
        name: repair.sha256_file(runtime_root / name)
        for name in BACKUP_FILES
        if (runtime_root / name).is_file() and not (runtime_root / name).is_symlink()
    }
    manifest = {
        "contract": CONTRACT,
        "host": socket.gethostname(),
        "previous_source_sha": context["previous_sha"],
        "files": files,
    }
    if destination.exists():
        if not manifest_path.is_file():
            raise UpgradeBlocked("upgrade_backup_collision")
        observed = json.loads(manifest_path.read_text(encoding="utf-8"))
        if observed != manifest:
            raise UpgradeBlocked("upgrade_backup_collision")
        for name, digest in files.items():
            stored = destination / name
            if not stored.is_file() or repair.sha256_file(stored) != digest:
                raise UpgradeBlocked("upgrade_backup_integrity_failed")
        return destination, observed

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=backup_id + ".", dir=destination.parent))
    try:
        for name in files:
            (staging / name).write_bytes((runtime_root / name).read_bytes())
        watchdog.atomic_json(staging / "manifest.json", manifest)
        os.replace(staging, destination)
    finally:
        if staging.exists():
            import shutil

            shutil.rmtree(staging)
    return destination, manifest


def restore_active_files(runtime_root: Path, backup_root: Path) -> None:
    for name in ("metadata.json", "run.py"):
        source = backup_root / name
        if not source.is_file():
            raise UpgradeBlocked("upgrade_backup_incomplete")
        repair.atomic_bytes(runtime_root / name, source.read_bytes())


def read_state(runtime_root: Path) -> dict[str, Any] | None:
    path = runtime_root / "state.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def apply_upgrade(context: dict[str, Any], *, timeout_seconds: int = 30) -> dict[str, Any]:
    runtime_root = context["runtime_root"]
    target_sha = context["target_sha"]
    backup_root, backup_manifest = create_backup(context)
    target_release, target_manifest = repair.stage_target_release(
        context["source_root"], runtime_root, target_sha
    )
    metadata = dict(context["metadata"])
    metadata.update(
        {
            "source_sha": target_sha,
            "release_root": str(target_release),
            "runtime_root": str(runtime_root),
            "upgrade_contract": CONTRACT,
            "upgrade_previous_source_sha": context["previous_sha"],
            "upgrade_backup_root": str(backup_root),
            "upgrade_started_at": watchdog.now_iso(),
            "headless_boot_ready": False,
        }
    )
    repair.atomic_bytes(runtime_root / "run.py", watchdog.launcher_bytes())
    watchdog.atomic_json(context["metadata_path"], metadata)
    was_running = context["task_runtime"].get("state") == 4
    handover = {"stopped": False}
    try:
        if was_running:
            handover = watchdog.stop_watchdog_task(runtime_root)
            if handover.get("stopped") is not True:
                raise UpgradeBlocked("watchdog_task_handover_not_proven")
        watchdog.run_watchdog_task()
        deadline = time.monotonic() + max(5, min(timeout_seconds, 60))
        observed_state = None
        while time.monotonic() < deadline:
            observed_state = read_state(runtime_root)
            if (
                observed_state
                and observed_state.get("source_sha") == target_sha
                and observed_state.get("ok") is True
                and observed_state.get("runner_recovery_ok") is True
            ):
                break
            time.sleep(1)
        else:
            raise UpgradeBlocked("s4u_watchdog_state_not_proven")

        process_after = watchdog.runner_process_snapshot(context["runner_home"])
        if process_after.get("matching_pids") != context["runner_process"].get("matching_pids"):
            raise UpgradeBlocked("runner_process_identity_changed")
        registry_after = runner.registry_snapshot(None)
        if not repair.registry_ready(registry_after) or registry_after.get("id") != context["registry"].get("id"):
            raise UpgradeBlocked("runner_registry_changed_after_upgrade")
        completed = dict(json.loads(context["metadata_path"].read_text(encoding="utf-8")))
        completed.update(
            {
                "upgrade_completed_at": watchdog.now_iso(),
                "headless_boot_ready": True,
                "activation_pending": False,
                "requires_uac_activation": False,
            }
        )
        watchdog.atomic_json(context["metadata_path"], completed)
        result = {
            "result": "CONTROL_PLANE_UPGRADED_PICKUP_PENDING",
            "host": socket.gethostname(),
            "source_sha": target_sha,
            "previous_source_sha": context["previous_sha"],
            "backup_root": str(backup_root),
            "backup_manifest": backup_manifest,
            "target_release": str(target_release),
            "target_release_manifest": target_manifest,
            "watchdog_task": watchdog.task_status(),
            "watchdog_state": observed_state,
            "runner_id": registry_after["id"],
            "runner_name": context["profile"].runner_name,
            "runner_process_preserved": True,
            "watchdog_task_handover": handover,
            "github_pickup_proven": False,
            "credentials_created": False,
            "todo_gateway_installed": False,
            "production_touched": False,
            "reboot_performed": False,
        }
        watchdog.atomic_json(runtime_root / "upgrade-evidence.json", result)
        return result
    except Exception as exc:
        restore_active_files(runtime_root, backup_root)
        if was_running:
            try:
                if watchdog.task_runtime_snapshot().get("state") == 4:
                    watchdog.stop_watchdog_task(runtime_root)
                watchdog.run_watchdog_task()
                deadline = time.monotonic() + max(5, min(timeout_seconds, 60))
                while time.monotonic() < deadline:
                    restored_state = read_state(runtime_root)
                    if (
                        restored_state
                        and restored_state.get("source_sha") == context["previous_sha"]
                        and restored_state.get("ok") is True
                        and restored_state.get("runner_recovery_ok") is True
                    ):
                        break
                    time.sleep(1)
                else:
                    raise UpgradeBlocked("watchdog_rollback_state_not_proven")
            except Exception as rollback_exc:
                raise UpgradeBlocked("watchdog_upgrade_rollback_failed") from rollback_exc
        raise exc


def preflight_result(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "result": "UPGRADE_PREFLIGHT_OK",
        "contract": CONTRACT,
        "host": socket.gethostname(),
        "source_sha": context["target_sha"],
        "previous_source_sha": context["previous_sha"],
        "watchdog_task": context["task"],
        "watchdog_task_runtime": context["task_runtime"],
        "runner_id": context["registry"]["id"],
        "runner_name": context["profile"].runner_name,
        "runner_status": context["registry"]["status"],
        "runner_busy": context["registry"]["busy"],
        "runner_pids": context["runner_process"]["matching_pids"],
        "mutation_performed": False,
        "github_pickup_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--expected-installed-sha", required=True)
    parser.add_argument("--expected-watchdog-sha256", required=True)
    parser.add_argument("--expected-uac-sha256", required=True)
    parser.add_argument("--expected-launcher-sha256", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRM:
        print(json.dumps({"result": "BLOCKED", "reason": "confirmation_invalid"}))
        return 2
    try:
        source = repair.source_root_and_sha(args.source_sha)
        context = inspect_active_installation(
            source,
            target_sha=args.source_sha,
            expected_installed_sha=args.expected_installed_sha,
            expected_watchdog_sha256=args.expected_watchdog_sha256,
            expected_uac_sha256=args.expected_uac_sha256,
            expected_launcher_sha256=args.expected_launcher_sha256,
        )
        result = preflight_result(context) if args.preflight_only else apply_upgrade(context)
    except (UpgradeBlocked, repair.RepairBlocked, watchdog.WatchdogError, runner.BootstrapError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"result": "BLOCKED", "reason": str(exc)[:200]}, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
