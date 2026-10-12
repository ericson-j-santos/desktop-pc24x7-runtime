#!/usr/bin/env python3
"""Read-only, host-pinned audit of ChatGPT Windows startup indicators.

No GUI, registry writes, subprocesses, remote calls, or credential inspection.
Results are deliberately non-authoritative until an interactive E2E after login.
"""
from __future__ import annotations

import ctypes
import json
import os
import re
import socket
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

HOST = "DESKTOP-PDQK954"
CORRELATION_PREFIX = "chatgpt-autostart-"
NAME = re.compile(r"chatgpt", re.IGNORECASE)
MAX_REGISTRY_VALUES = 512
MAX_PACKAGE_KEYS = 2048

REGISTRATIONS = (
    ("current_user", "HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("all_users", "HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("all_users_32bit", "HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run32"),
)
APPROVAL_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


class AuditBlocked(RuntimeError):
    """Fixed error code only; do not leak paths or registry values."""


def approval_state(value: object) -> str:
    if not isinstance(value, bytes) or not value:
        return "unknown"
    # Windows StartupApproved uses 0x02 = enabled, 0x03 = disabled.
    return {2: "enabled", 3: "disabled"}.get(value[0], "unknown")


def classify(evidence: dict) -> str:
    if evidence.get("host_confirmed") is not True:
        return "blocked_host_mismatch"
    entries = evidence.get("entries") or []
    verified_context = evidence.get("runner_matches_active_console") is True
    package_seen = evidence.get("package_current_user") is True
    if not entries:
        return "inconclusive_no_matching_registration_in_scanned_sources"
    eligible = [e for e in entries if e.get("registration") == "run" and e.get("approval") == "enabled"]
    if eligible and verified_context and package_seen and any(e["scope"] == "current_user" for e in eligible):
        return "startup_registration_enabled_for_current_interactive_runner"
    if all(e.get("approval") == "disabled" for e in entries):
        return "registered_but_disabled_in_scanned_sources"
    return "inconclusive_session_identity_or_registration"


def _enum_value_names_only(winreg, hive, path: str) -> list[str]:
    """RegEnumValueW with NULL lpData avoids reading unrelated Run command contents."""
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            count = winreg.QueryInfoKey(key)[1]
            if count > MAX_REGISTRY_VALUES:
                raise AuditBlocked("registry_value_limit_exceeded")
            fn = ctypes.windll.advapi32.RegEnumValueW
            fn.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.LPWSTR,
                           ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            fn.restype = wintypes.LONG
            names = []
            for i in range(count):
                buf = ctypes.create_unicode_buffer(8193)
                size = wintypes.DWORD(8192)
                code = fn(ctypes.c_void_p(int(key)), i, buf, ctypes.byref(size),
                          None, None, None, None)
                if code != 0:
                    raise AuditBlocked("registry_name_enumeration_failed")
                names.append(buf.value)
            return names
    except FileNotFoundError:
        return []
    except PermissionError:
        raise AuditBlocked("registry_read_denied") from None


def _approval(winreg, hive, subkey: str, name: str) -> str:
    path = APPROVAL_BASE + "\\" + subkey
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            data, _ = winreg.QueryValueEx(key, name)
        return approval_state(data)
    except FileNotFoundError:
        return "not_registered"
    except PermissionError:
        return "unknown"


def _package_present(winreg) -> bool | None:
    path = (r"Software\Classes\Local Settings\Software\Microsoft\Windows"
            r"\CurrentVersion\AppModel\Repository\Packages")
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
            count = winreg.QueryInfoKey(key)[0]
            if count > MAX_PACKAGE_KEYS:
                return None
            return any(NAME.search(winreg.EnumKey(key, i)) for i in range(count))
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _session_context() -> tuple[int | None, int | None, bool]:
    try:
        api = ctypes.windll.kernel32
        api.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
        api.GetCurrentProcessId.restype = wintypes.DWORD
        api.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        api.ProcessIdToSessionId.restype = wintypes.BOOL
        console = int(api.WTSGetActiveConsoleSessionId())
        local = wintypes.DWORD()
        if console == 0xFFFFFFFF or not api.ProcessIdToSessionId(api.GetCurrentProcessId(), ctypes.byref(local)):
            return None, None, False
        return int(local.value), console, int(local.value) == console
    except (AttributeError, OSError, ValueError):
        return None, None, False


def _autologon(winreg) -> str:
    # Only the boolean flag is queried; never read account or password values.
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "AutoAdminLogon")
        return "enabled" if str(value).strip() == "1" else "disabled"
    except (FileNotFoundError, PermissionError, OSError):
        return "unknown"


def collect() -> dict:
    if os.name != "nt" or socket.gethostname().casefold() != HOST.casefold():
        raise AuditBlocked("host_or_platform_not_authorized")
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("GITHUB_REPOSITORY") != "ericson-j-santos/desktop-pc24x7-runtime"):
        raise AuditBlocked("github_runner_context_missing")
    if os.environ.get("GITHUB_RUN_ATTEMPT") != "1":
        raise AuditBlocked("automatic_rerun_not_authorized")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    sha = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise AuditBlocked("github_run_identity_invalid")

    import winreg

    entries: list[dict] = []
    checked = []
    for scope, hive_name, path, approval_subkey in REGISTRATIONS:
        hive = getattr(winreg, hive_name)
        names = _enum_value_names_only(winreg, hive, path)
        checked.append("run_" + scope)
        for name in names:
            if NAME.search(name):
                entries.append({"scope": scope, "registration": "run",
                                "approval": _approval(winreg, hive, approval_subkey, name),
                                "target_verified": False})

    folder_defs = (
        ("current_user", os.environ.get("APPDATA", ""), ("Microsoft", "Windows", "Start Menu", "Programs", "Startup")),
        ("all_users", os.environ.get("PROGRAMDATA", ""), ("Microsoft", "Windows", "Start Menu", "Programs", "Startup")),
    )
    for scope, root, suffix in folder_defs:
        if not root:
            checked.append("startup_folder_" + scope + "_unavailable")
            continue
        folder = Path(root).joinpath(*suffix)
        checked.append("startup_folder_" + scope)
        if folder.is_dir():
            try:
                for f in folder.iterdir():
                    if NAME.search(f.name) and f.suffix.lower() in {".lnk", ".url"}:
                        hive = winreg.HKEY_CURRENT_USER if scope == "current_user" else winreg.HKEY_LOCAL_MACHINE
                        entries.append({"scope": scope, "registration": "startup_folder",
                                        "approval": _approval(winreg, hive, "StartupFolder", f.name),
                                        "target_verified": False})
            except PermissionError:
                checked.append("startup_folder_" + scope + "_denied")

    for scope, hive in (("current_user", winreg.HKEY_CURRENT_USER),
                        ("all_users", winreg.HKEY_LOCAL_MACHINE)):
        key_path = APPROVAL_BASE + "\\StartupTasks"
        checked.append("startup_tasks_" + scope)
        for name in _enum_value_names_only(winreg, hive, key_path):
            if NAME.search(name):
                entries.append({"scope": scope, "registration": "startup_task",
                                "approval": _approval(winreg, hive, "StartupTasks", name),
                                "target_verified": False})

    session_id, console_id, console_match = _session_context()
    payload = {
        "schema_version": "chatgpt-startup-audit/v1", "environment": "local/dev",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "host": HOST, "host_confirmed": True,
        "runtime_sha": sha, "github_run_id": run_id,
        "correlation_id": CORRELATION_PREFIX + run_id,
        "runner_session_id": session_id, "active_console_session_id": console_id,
        "runner_matches_active_console": console_match,
        "auto_admin_logon_flag": _autologon(winreg),
        "package_current_user": _package_present(winreg),
        "entries": entries, "sources_checked": sorted(checked),
        "scheduled_task_triggers_checked": False,
        "app_executable_identity_verified": False,
        "chatgpt_autostart_after_reboot_verified": False,
        "startup_registry_mutated": False, "reboot_performed": False,
        "passwords_or_run_values_read": False,
    }
    payload["assessment"] = classify(payload)
    return payload


def main() -> int:
    try:
        evidence = collect()
    except AuditBlocked as error:
        evidence = {"schema_version": "chatgpt-startup-audit/v1",
                    "assessment": "blocked", "reason": str(error),
                    "chatgpt_autostart_after_reboot_verified": False,
                    "reboot_performed": False}
    except Exception:
        evidence = {"schema_version": "chatgpt-startup-audit/v1",
                    "assessment": "blocked", "reason": "audit_unexpected_error",
                    "chatgpt_autostart_after_reboot_verified": False,
                    "reboot_performed": False}
    serialized = json.dumps(evidence, sort_keys=True)
    print("CHATGPT_STARTUP_AUDIT=" + serialized)
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp and os.environ.get("GITHUB_ACTIONS") == "true":
        target = Path(runner_temp) / "chatgpt-autostart-evidence.json"
        target.write_text(serialized + "\n", encoding="utf-8")
    return 2 if evidence.get("assessment") == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
