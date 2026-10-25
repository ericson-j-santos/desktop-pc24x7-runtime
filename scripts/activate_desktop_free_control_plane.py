#!/usr/bin/env python3
"""Ativa runner e watchdog existentes em um desktop autorizado, uma única vez."""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path

import bootstrap_dedicated_runtime_runner as runner
import desktop_control_plane_watchdog as watchdog
import desktop_control_plane_watchdog_uac_launcher as uac

CONFIRM = "ACTIVATE-DESKTOP-FREE-CONTROL-PLANE"


class ActivationBlocked(RuntimeError):
    pass


def source_root_and_sha(expected_sha: str) -> Path:
    root = Path(__file__).resolve().parents[1]
    if len(expected_sha) != 40 or any(c not in "0123456789abcdefABCDEF" for c in expected_sha):
        raise ActivationBlocked("source_sha_invalid")
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
        raise ActivationBlocked("source_git_unavailable") from exc
    if head.returncode or status.returncode or head.stdout.strip().lower() != expected_sha.lower() or status.stdout.strip():
        raise ActivationBlocked("source_sha_or_cleanliness_mismatch")
    return root


def preflight(source_root: Path) -> Path:
    host = watchdog.require_windows_desktop()
    if host.casefold() != socket.gethostname().casefold():
        raise ActivationBlocked("host_identity_changed")
    if watchdog.task_status().get("exists"):
        raise ActivationBlocked("existing_watchdog_task_requires_separate_upgrade")
    if (watchdog.default_runtime_root() / "metadata.json").exists():
        raise ActivationBlocked("existing_watchdog_metadata_requires_separate_upgrade")
    for name in (watchdog.RDC_RECOVERY_SCRIPT, watchdog.UAC_LAUNCHER_SCRIPT, watchdog.HOST_POLICY_SCRIPT):
        if not (source_root / "scripts" / name).is_file():
            raise ActivationBlocked("source_bundle_incomplete")
    try:
        import win32com.client  # type: ignore  # noqa: F401
    except ImportError as exc:
        raise ActivationBlocked("pywin32_required") from exc
    runner.validate_host()
    if runner.find_gh() is None:
        raise ActivationBlocked("github_cli_required")
    try:
        runner.local_gh_api_json(f"repos/{runner.REPOSITORY}/actions/runners")
    except runner.BootstrapError as exc:
        raise ActivationBlocked(exc.state) from None
    return runner.default_runner_home().resolve()


def activate(expected_sha: str) -> dict:
    source = source_root_and_sha(expected_sha)
    runner_home = preflight(source)
    registered = runner.bootstrap(source_sha=expected_sha)
    if not registered.get("ok"):
        raise ActivationBlocked(str(registered.get("state") or "runner_not_ready"))
    installed = watchdog.install(
        source,
        source_sha=expected_sha,
        python_executable=Path(sys.executable),
        runner_home=runner_home,
        runtime_root=watchdog.default_runtime_root(),
        watch_interval_seconds=watchdog.DEFAULT_WATCH_SECONDS,
        confirm=watchdog.CONFIRM,
    )
    if installed.get("requires_uac_activation"):
        activation = uac.launch(
            watchdog.default_runtime_root() / "metadata.json",
            confirm=uac.LAUNCH_CONFIRM,
            timeout_seconds=120,
        )
        if not activation.get("ok"):
            raise ActivationBlocked("uac_approval_or_provisioning_pending")
    task = watchdog.task_status()
    if not uac.task_headless_ready(task):
        raise ActivationBlocked("atstartup_s4u_not_verified")
    return {
        "result": "CONTROL_PLANE_INSTALLED_PICKUP_PENDING",
        "host": socket.gethostname(),
        "source_sha": expected_sha.lower(),
        "runner_name": registered["runner_name"],
        "runner_running": registered["runner_running"],
        "watchdog_task": task,
        "github_pickup_proven": False,
        "production_touched": False,
        "reboot_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRM:
        print(json.dumps({"result": "BLOCKED", "reason": "confirmation_invalid"}))
        return 2
    try:
        result = activate(args.source_sha)
    except (ActivationBlocked, runner.BootstrapError, watchdog.WatchdogError,
            OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        if isinstance(exc, runner.BootstrapError):
            reason = exc.state
        elif isinstance(exc, ActivationBlocked):
            reason = str(exc)
        else:
            reason = type(exc).__name__
        print(json.dumps({"result": "BLOCKED", "reason": reason[:120]}, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
