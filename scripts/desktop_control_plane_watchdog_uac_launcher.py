#!/usr/bin/env python3
"""Launcher UAC governado para ativar o watchdog autônomo do Desktop PC24x7."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import desktop_control_plane_watchdog as watchdog

LAUNCH_CONFIRM = "LAUNCH-DESKTOP-CONTROL-PLANE-WATCHDOG-UAC"
SW_SHOWNORMAL = 1


def validate_launcher(*, host: str, platform: str, confirm: str) -> None:
    if platform != "nt":
        raise RuntimeError("launcher UAC exige Windows")
    try:
        watchdog.authorized_desktop_profile(host)
    except watchdog.WatchdogError as exc:
        raise RuntimeError(str(exc)) from None
    if confirm != LAUNCH_CONFIRM:
        raise RuntimeError("confirmação UAC inválida")


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def default_metadata_path() -> Path:
    return watchdog.default_runtime_root() / "metadata.json"


def task_headless_ready(task: dict[str, Any]) -> bool:
    return (
        task.get("exists") is True
        and task.get("trigger_at_startup") is True
        and str(task.get("logon_type") or "").casefold() == "s4u"
    )


def load_installation(metadata_path: Path) -> dict[str, Any]:
    return watchdog.load_installed_metadata(
        metadata_path.resolve(),
        require_current_release=False,
    )


def uac_receipt_path(installation: dict[str, Any]) -> Path:
    return installation["metadata_path"].resolve().parent / "uac-result.json"


def build_elevated_arguments(
    installation: dict[str, Any], invocation_id: str
) -> str:
    argv = [
        str(installation["release_watchdog"]),
        "register-task-com",
        "--metadata",
        str(installation["metadata_path"]),
        "--receipt",
        str(uac_receipt_path(installation)),
        "--invocation-id",
        invocation_id,
    ]
    return subprocess.list2cmdline(argv)


def matching_receipt(path: Path, invocation_id: str) -> dict[str, Any] | None:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("invocation_id") != invocation_id:
        return None
    return payload


def shell_execute_runas(executable: Path, params: str, cwd: Path) -> int:
    return int(
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            str(executable),
            params,
            str(cwd),
            SW_SHOWNORMAL,
        )
    )


def finalize_activation(installation: dict[str, Any]) -> dict[str, Any]:
    task = watchdog.task_status()
    if not task_headless_ready(task):
        raise RuntimeError("AtStartup S4U não foi verificado")
    metadata = dict(installation["metadata"])
    metadata.update(
        {
            "headless_boot_ready": True,
            "activation_pending": False,
            "requires_uac_activation": False,
            "uac_activated_at": watchdog.now_iso(),
        }
    )
    watchdog.atomic_json(installation["metadata_path"], metadata)
    started = watchdog.run_watchdog_task()
    return {"metadata": metadata, "task": task, "start": started}


def launch(metadata_path: Path, *, confirm: str, timeout_seconds: int) -> dict[str, Any]:
    validate_launcher(host=socket.gethostname(), platform=os.name, confirm=confirm)
    installation = load_installation(metadata_path)

    current = watchdog.task_status()
    if task_headless_ready(current):
        finalized = finalize_activation(installation)
        return {
            "ok": True,
            "mode": "already_ready",
            "result": "DESKTOP_CONTROL_PLANE_WATCHDOG_READY",
            **finalized,
        }

    if is_admin():
        watchdog.register_task_from_metadata(installation["metadata_path"])
        finalized = finalize_activation(installation)
        return {
            "ok": True,
            "mode": "already_elevated",
            "result": "DESKTOP_CONTROL_PLANE_WATCHDOG_PROVISIONED",
            **finalized,
        }

    invocation_id = uuid.uuid4().hex
    receipt_path = uac_receipt_path(installation)
    watchdog.atomic_json(
        receipt_path,
        {
            "ok": None,
            "invocation_id": invocation_id,
            "started_at": watchdog.now_iso(),
            "state": "uac_pending",
        },
    )
    rc = shell_execute_runas(
        installation["python_executable"],
        build_elevated_arguments(installation, invocation_id),
        installation["release_root"],
    )
    if rc <= 32:
        raise RuntimeError(f"uac_launch_failed:{rc}")

    deadline = time.monotonic() + max(5, min(timeout_seconds, 120))
    while time.monotonic() < deadline:
        task = watchdog.task_status()
        if task_headless_ready(task):
            finalized = finalize_activation(installation)
            return {
                "ok": True,
                "mode": "uac",
                "result": "DESKTOP_CONTROL_PLANE_WATCHDOG_PROVISIONED",
                **finalized,
            }
        receipt = matching_receipt(receipt_path, invocation_id)
        if receipt and receipt.get("ok") is False:
            error = str(receipt.get("error") or "unknown")[:500]
            raise RuntimeError(f"uac_registration_failed:{error}")
        time.sleep(1.0)

    return {
        "ok": False,
        "mode": "uac",
        "result": "UAC_APPROVAL_OR_PROVISIONING_PENDING",
        "task": watchdog.task_status(),
        "uac_receipt": matching_receipt(receipt_path, invocation_id),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ativa AtStartup S4U do watchdog do Desktop PC24x7 via UAC"
    )
    parser.add_argument("--metadata", type=Path, default=None)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args()
    try:
        result = launch(
            args.metadata or default_metadata_path(),
            confirm=args.confirm,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, watchdog.WatchdogError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
