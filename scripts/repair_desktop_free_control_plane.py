#!/usr/bin/env python3
"""Repair a partial Desktop free control-plane installation without replaying bootstrap."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import bootstrap_dedicated_runtime_runner as runner
import desktop_control_plane_watchdog as watchdog
import desktop_control_plane_watchdog_uac_launcher as uac
from pc24x7_host_policy import authorized_host

CONFIRM = "REPAIR-DESKTOP-FREE-CONTROL-PLANE"
CONTRACT = "desktop-free-control-plane-partial-repair-v1"
TARGET_RELEASE_FILES = (
    "desktop_control_plane_watchdog.py",
    "desktop_control_plane_watchdog_uac_launcher.py",
    "pc24x7_host_policy.py",
    "pc24x7_rdc_recovery.py",
)
BACKUP_FILES = (
    "metadata.json",
    "run.py",
    "install-evidence.json",
    "uac-result.json",
    "schtasks-result.txt",
)
ROLLBACK_FILES = (
    "metadata.json",
    "run.py",
)


class RepairBlocked(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha(value: str, reason: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 40 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise RepairBlocked(reason)
    return normalized


def require_digest(value: str, reason: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise RepairBlocked(reason)
    return normalized


def source_root_and_sha(expected_sha: str) -> Path:
    expected = require_sha(expected_sha, "source_sha_invalid")
    root = Path(__file__).resolve().parents[1]
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepairBlocked("source_git_unavailable") from exc
    if head.returncode or status.returncode:
        raise RepairBlocked("source_git_unavailable")
    if head.stdout.strip().lower() != expected or status.stdout.strip():
        raise RepairBlocked("source_sha_or_cleanliness_mismatch")
    return root


def configure_runner_contract(host: str) -> Any:
    profile = authorized_host(host)
    if profile.role not in {"desktop-primary", "desktop-secondary"}:
        raise RepairBlocked("host_not_authorized")
    runner.RUNNER_NAME = profile.runner_name
    runner.RUNNER_LABELS = profile.runner_labels
    runner.REQUIRED_LABELS = (
        "self-hosted", "Windows", "X64",
        *tuple(label for label in profile.runner_labels.split(",") if label),
    )
    return profile


def read_metadata(metadata_path: Path, runtime_root: Path) -> dict[str, Any]:
    if metadata_path.resolve() != (runtime_root / "metadata.json").resolve():
        raise RepairBlocked("metadata_path_invalid")
    if not metadata_path.is_file() or metadata_path.is_symlink():
        raise RepairBlocked("existing_watchdog_metadata_required")
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RepairBlocked("existing_watchdog_metadata_invalid") from exc
    if not isinstance(payload, dict):
        raise RepairBlocked("existing_watchdog_metadata_invalid")
    return payload


def fixed_release_file(release_root: Path, name: str) -> Path:
    path = (release_root / "scripts" / name).resolve()
    scripts = (release_root / "scripts").resolve()
    if path.parent != scripts or not path.is_file() or path.is_symlink():
        raise RepairBlocked(f"installed_release_file_invalid:{name}")
    return path


def registry_ready(snapshot: dict[str, Any]) -> bool:
    return bool(
        snapshot.get("present") is True
        and isinstance(snapshot.get("id"), int)
        and snapshot["id"] > 0
        and snapshot.get("status") == "online"
        and snapshot.get("busy") is False
        and snapshot.get("labels_ok") is True
    )


def inspect_partial_installation(
    source_root: Path,
    *,
    target_sha: str,
    expected_installed_sha: str,
    expected_watchdog_sha256: str,
    expected_uac_sha256: str,
) -> dict[str, Any]:
    target = require_sha(target_sha, "source_sha_invalid")
    previous = require_sha(expected_installed_sha, "expected_installed_sha_invalid")
    expected_watchdog = require_digest(
        expected_watchdog_sha256, "expected_watchdog_sha256_invalid"
    )
    expected_uac = require_digest(expected_uac_sha256, "expected_uac_sha256_invalid")
    host = watchdog.require_windows_desktop()
    if host.casefold() != socket.gethostname().casefold():
        raise RepairBlocked("host_identity_changed")
    profile = configure_runner_contract(host)
    runtime_root = watchdog.default_runtime_root().resolve()
    metadata_path = runtime_root / "metadata.json"
    metadata = read_metadata(metadata_path, runtime_root)
    observed_host = str(metadata.get("host") or "")
    if observed_host.casefold() != host.casefold():
        raise RepairBlocked("installed_metadata_host_mismatch")
    observed_sha = require_sha(
        str(metadata.get("source_sha") or ""), "installed_source_sha_invalid"
    )

    task = watchdog.task_status()
    if observed_sha == target and uac.task_headless_ready(task):
        return {
            "already_repaired": True,
            "host": host,
            "profile": profile,
            "runtime_root": runtime_root,
            "metadata_path": metadata_path,
            "metadata": metadata,
            "task": task,
        }
    if observed_sha != previous:
        raise RepairBlocked("installed_source_sha_changed")
    if task.get("exists"):
        raise RepairBlocked("existing_watchdog_task_requires_separate_upgrade")

    release_root = Path(str(metadata.get("release_root") or "")).resolve()
    if release_root != runtime_root / "releases" / previous:
        raise RepairBlocked("installed_release_root_mismatch")
    installed_watchdog = fixed_release_file(
        release_root, "desktop_control_plane_watchdog.py"
    )
    installed_uac = fixed_release_file(
        release_root, "desktop_control_plane_watchdog_uac_launcher.py"
    )
    watchdog_digest = sha256_file(installed_watchdog)
    uac_digest = sha256_file(installed_uac)
    if watchdog_digest != expected_watchdog:
        raise RepairBlocked("installed_watchdog_digest_changed")
    if uac_digest != expected_uac:
        raise RepairBlocked("installed_uac_digest_changed")

    runner_home = Path(str(metadata.get("runner_home") or "")).resolve()
    watchdog.validate_runner_home(runner_home)
    process = watchdog.runner_process_snapshot(runner_home)
    if len(process.get("matching_pids") or []) != 1:
        raise RepairBlocked("existing_runner_process_not_unique")
    registry = runner.registry_snapshot(None)
    if not registry_ready(registry):
        raise RepairBlocked("existing_runner_registry_not_idle_online")
    python_executable = Path(str(metadata.get("python_executable") or "")).resolve()
    if not python_executable.is_file():
        raise RepairBlocked("installed_python_missing")
    try:
        orphan_task_file = watchdog.inspect_orphaned_task_file(
            python_executable=python_executable,
            launcher=runtime_root / "run.py",
        )
    except watchdog.WatchdogError as exc:
        raise RepairBlocked(str(exc)) from None
    try:
        import win32com.client  # type: ignore  # noqa: F401
    except ImportError as exc:
        raise RepairBlocked("pywin32_required") from exc
    try:
        watchdog.task_security_descriptor(
            watchdog.current_user_sid(watchdog.current_user_id())
        )
    except watchdog.WatchdogError as exc:
        raise RepairBlocked(str(exc)) from None
    for name in TARGET_RELEASE_FILES:
        if not (source_root / "scripts" / name).is_file():
            raise RepairBlocked(f"source_bundle_incomplete:{name}")
    return {
        "already_repaired": False,
        "host": host,
        "profile": profile,
        "runtime_root": runtime_root,
        "metadata_path": metadata_path,
        "metadata": metadata,
        "task": task,
        "previous_sha": previous,
        "previous_release_root": release_root,
        "installed_watchdog_sha256": watchdog_digest,
        "installed_uac_sha256": uac_digest,
        "runner_home": runner_home,
        "runner_process": process,
        "registry": registry,
        "python_executable": python_executable,
        "orphan_task_file": orphan_task_file,
        "task_acl_preflight": True,
    }


def atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def create_backup(context: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    runtime_root = context["runtime_root"]
    backup_id = context["previous_sha"] + "-" + context["installed_watchdog_sha256"][:16]
    destination = runtime_root / "backups" / backup_id
    manifest_path = destination / "manifest.json"
    expected_files: dict[str, str] = {}
    for name in BACKUP_FILES:
        current = runtime_root / name
        if current.is_file() and not current.is_symlink():
            expected_files[name] = sha256_file(current)
    manifest = {
        "contract": CONTRACT,
        "host": context["host"],
        "previous_source_sha": context["previous_sha"],
        "previous_release_root": str(context["previous_release_root"]),
        "installed_watchdog_sha256": context["installed_watchdog_sha256"],
        "installed_uac_sha256": context["installed_uac_sha256"],
        "files": expected_files,
    }
    if destination.exists():
        if not manifest_path.is_file():
            raise RepairBlocked("backup_collision")
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_identity = {
            key: value for key, value in manifest.items() if key != "files"
        }
        existing_identity = {
            key: value for key, value in existing.items() if key != "files"
        }
        if existing_identity != expected_identity:
            raise RepairBlocked("backup_collision")
        stored_files = existing.get("files")
        if not isinstance(stored_files, dict):
            raise RepairBlocked("backup_collision")
        for name, digest in stored_files.items():
            stored = destination / name
            if (
                name not in BACKUP_FILES
                or not isinstance(digest, str)
                or not stored.is_file()
                or stored.is_symlink()
                or sha256_file(stored) != digest
            ):
                raise RepairBlocked("backup_integrity_failed")
        for name in ROLLBACK_FILES:
            current = runtime_root / name
            digest = stored_files.get(name)
            if (
                not isinstance(digest, str)
                or not current.is_file()
                or current.is_symlink()
                or sha256_file(current) != digest
            ):
                raise RepairBlocked("backup_active_state_changed")
        return destination, existing

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=backup_id + ".", dir=destination.parent))
    try:
        for name in expected_files:
            shutil.copy2(runtime_root / name, staging / name)
        watchdog.atomic_json(staging / "manifest.json", manifest)
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return destination, manifest


def source_release_manifest(source_root: Path, target_sha: str) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "source_sha": target_sha,
        "files": {
            name: sha256_file(source_root / "scripts" / name)
            for name in TARGET_RELEASE_FILES
        },
    }


def stage_target_release(source_root: Path, runtime_root: Path, target_sha: str) -> tuple[Path, dict[str, Any]]:
    releases = runtime_root / "releases"
    target = releases / target_sha
    manifest = source_release_manifest(source_root, target_sha)
    manifest_path = target / "release-manifest.json"
    if target.exists():
        if not manifest_path.is_file():
            raise RepairBlocked("target_release_collision")
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing != manifest:
            raise RepairBlocked("target_release_collision")
        for name, digest in manifest["files"].items():
            if sha256_file(target / "scripts" / name) != digest:
                raise RepairBlocked("target_release_integrity_failed")
        return target, manifest

    releases.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=target_sha + ".", dir=releases))
    try:
        scripts = staging / "scripts"
        scripts.mkdir()
        for name in TARGET_RELEASE_FILES:
            shutil.copy2(source_root / "scripts" / name, scripts / name)
        watchdog.atomic_json(staging / "release-manifest.json", manifest)
        os.replace(staging, target)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return target, manifest


def launcher_bytes() -> bytes:
    return watchdog.launcher_bytes()


def restore_active_files(runtime_root: Path, backup_root: Path) -> None:
    for name in ("run.py", "metadata.json"):
        source = backup_root / name
        if not source.is_file():
            raise RepairBlocked("rollback_backup_incomplete")
        atomic_bytes(runtime_root / name, source.read_bytes())


def activate_repair(
    source_root: Path,
    context: dict[str, Any],
    *,
    target_sha: str,
) -> dict[str, Any]:
    if context.get("already_repaired"):
        return {
            "result": "CONTROL_PLANE_ALREADY_REPAIRED",
            "host": context["host"],
            "source_sha": target_sha,
            "watchdog_task": context["task"],
            "github_pickup_proven": False,
            "replay_mutation": False,
        }
    runtime_root = context["runtime_root"]
    backup_root, backup_manifest = create_backup(context)
    target_release, target_manifest = stage_target_release(
        source_root, runtime_root, target_sha
    )
    metadata = dict(context["metadata"])
    metadata.update({
        "source_sha": target_sha,
        "release_root": str(target_release),
        "repair_contract": CONTRACT,
        "repair_previous_source_sha": context["previous_sha"],
        "repair_backup_root": str(backup_root),
        "repair_started_at": now_iso(),
        "activation_pending": True,
        "headless_boot_ready": False,
        "requires_uac_activation": True,
    })
    atomic_bytes(runtime_root / "run.py", launcher_bytes())
    watchdog.atomic_json(context["metadata_path"], metadata)
    try:
        try:
            watchdog.register_boot_task(
                python_executable=context["python_executable"],
                launcher=runtime_root / "run.py",
            )
            mode = "already_elevated"
            finalized = uac.finalize_activation(
                watchdog.load_installed_metadata(context["metadata_path"])
            )
        except watchdog.WatchdogError as exc:
            if str(exc) != "task_scheduler_access_denied":
                raise
            activation = uac.launch(
                context["metadata_path"],
                confirm=uac.LAUNCH_CONFIRM,
                timeout_seconds=120,
            )
            if not activation.get("ok"):
                raise RepairBlocked("uac_approval_or_provisioning_pending")
            mode = str(activation.get("mode") or "uac")
            finalized = activation
        task = watchdog.task_status()
        if not uac.task_headless_ready(task):
            raise RepairBlocked("atstartup_s4u_not_verified")
        process_after = watchdog.runner_process_snapshot(context["runner_home"])
        before_pids = context["runner_process"].get("matching_pids") or []
        after_pids = process_after.get("matching_pids") or []
        if after_pids != before_pids:
            raise RepairBlocked("runner_process_identity_changed")
        registry_after = runner.registry_snapshot(None)
        if not registry_ready(registry_after):
            raise RepairBlocked("runner_registry_changed_after_repair")
        if registry_after.get("id") != context["registry"].get("id"):
            raise RepairBlocked("runner_registry_identity_changed")
        completed = dict(json.loads(context["metadata_path"].read_text(encoding="utf-8")))
        completed.update({
            "repair_completed_at": now_iso(),
            "activation_pending": False,
            "headless_boot_ready": True,
            "requires_uac_activation": False,
        })
        watchdog.atomic_json(context["metadata_path"], completed)
        result = {
            "result": "CONTROL_PLANE_REPAIRED_PICKUP_PENDING",
            "host": context["host"],
            "source_sha": target_sha,
            "previous_source_sha": context["previous_sha"],
            "backup_root": str(backup_root),
            "backup_manifest": backup_manifest,
            "target_release": str(target_release),
            "target_release_manifest": target_manifest,
            "activation_mode": mode,
            "watchdog_task": task,
            "runner_name": context["profile"].runner_name,
            "runner_id": registry_after["id"],
            "runner_running": True,
            "runner_process_preserved": True,
            "github_pickup_proven": False,
            "production_touched": False,
            "reboot_performed": False,
            "credentials_created": False,
            "todo_gateway_installed": False,
            "finalized": bool(finalized),
        }
        watchdog.atomic_json(runtime_root / "repair-evidence.json", result)
        return result
    except Exception:
        task = watchdog.task_status()
        if not uac.task_headless_ready(task):
            restore_active_files(runtime_root, backup_root)
        raise


def preflight_result(context: dict[str, Any], target_sha: str) -> dict[str, Any]:
    registry = context.get("registry") or {}
    process = context.get("runner_process") or {}
    profile = context.get("profile")
    return {
        "result": "REPAIR_PREFLIGHT_OK",
        "contract": CONTRACT,
        "host": context["host"],
        "source_sha": target_sha,
        "previous_source_sha": context.get("previous_sha", target_sha),
        "already_repaired": bool(context.get("already_repaired")),
        "watchdog_task": context["task"],
        "installed_watchdog_sha256": context.get("installed_watchdog_sha256"),
        "installed_uac_sha256": context.get("installed_uac_sha256"),
        "runner_name": getattr(profile, "runner_name", None),
        "runner_id": registry.get("id"),
        "runner_status": registry.get("status"),
        "runner_busy": registry.get("busy"),
        "runner_pids": process.get("matching_pids", []),
        "orphan_task_file": context.get("orphan_task_file"),
        "task_acl_preflight": bool(context.get("task_acl_preflight")),
        "mutation_performed": False,
        "github_pickup_proven": False,
    }


def repair(
    *,
    target_sha: str,
    expected_installed_sha: str,
    expected_watchdog_sha256: str,
    expected_uac_sha256: str,
) -> dict[str, Any]:
    source = source_root_and_sha(target_sha)
    context = inspect_partial_installation(
        source,
        target_sha=target_sha,
        expected_installed_sha=expected_installed_sha,
        expected_watchdog_sha256=expected_watchdog_sha256,
        expected_uac_sha256=expected_uac_sha256,
    )
    return activate_repair(source, context, target_sha=target_sha)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--expected-installed-sha", required=True)
    parser.add_argument("--expected-watchdog-sha256", required=True)
    parser.add_argument("--expected-uac-sha256", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRM:
        print(json.dumps({"result": "BLOCKED", "reason": "confirmation_invalid"}))
        return 2
    try:
        source = source_root_and_sha(args.source_sha)
        context = inspect_partial_installation(
            source,
            target_sha=args.source_sha,
            expected_installed_sha=args.expected_installed_sha,
            expected_watchdog_sha256=args.expected_watchdog_sha256,
            expected_uac_sha256=args.expected_uac_sha256,
        )
        result = (
            preflight_result(context, args.source_sha)
            if args.preflight_only
            else activate_repair(source, context, target_sha=args.source_sha)
        )
    except (RepairBlocked, runner.BootstrapError, watchdog.WatchdogError,
            OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        reason = (
            str(exc)
            if isinstance(exc, (RepairBlocked, RuntimeError))
            else type(exc).__name__
        )
        print(json.dumps({"result": "BLOCKED", "reason": reason[:160]}, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
