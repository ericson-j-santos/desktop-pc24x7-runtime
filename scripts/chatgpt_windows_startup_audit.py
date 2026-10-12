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
NAME = re.compile(r"chatgpt|codex|openai", re.IGNORECASE)
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
        if evidence.get("installation_candidates"):
            return "inconclusive_installation_hint_without_enabled_startup"
        return "inconclusive_no_matching_registration_in_scanned_sources"
    eligible = [e for e in entries if e.get("registration") == "run" and e.get("approval") == "enabled"]
    if (eligible and verified_context and package_seen
            and evidence.get("runner_account_matches_console_username") is True
            and any(e["scope"] == "current_user" for e in eligible)):
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
    except FileNotFoundError:
        return "not_configured"
    except (PermissionError, OSError):
        return "unknown"



def candidate_kind(name: str) -> str | None:
    """Return a product family only, never raw filenames or user identities."""
    if not isinstance(name, str):
        return None
    value = name.casefold().replace(" ", "").replace("-", "").replace("_", "")
    if "chatgpt" in value:
        return "chatgpt"
    if "codex" in value:
        return "codex"
    if "openai" in value:
        return "openai_unresolved"
    return None


def _package_candidates(winreg) -> tuple[list[dict], list[str]]:
    roots = (
        ("current_user", winreg.HKEY_CURRENT_USER,
         r"Software\Classes\Local Settings\Software\Microsoft\Windows"
         r"\CurrentVersion\AppModel\Repository\Packages"),
        ("machine", winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications"),
    )
    results, checks = [], []
    for scope, hive, path in roots:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[0]
                if count > MAX_PACKAGE_KEYS:
                    checks.append("package_" + scope + "_limit_exceeded")
                    continue
                checks.append("package_" + scope)
                for index in range(count):
                    kind = candidate_kind(winreg.EnumKey(key, index))
                    if kind:
                        results.append({"scope": scope, "kind": kind,
                                        "signal": "package_registry_name_only"})
        except FileNotFoundError:
            checks.append("package_" + scope + "_not_present")
        except (PermissionError, OSError):
            checks.append("package_" + scope + "_not_readable")
    return results, checks


def _directory_candidates() -> tuple[list[dict], list[str]]:
    """Only fixed app locations; never dereference shortcuts or read file bodies."""
    candidates, checks = [], []
    locations = (
        ("user_programs", "LOCALAPPDATA", ("Programs",)),
        ("user_app_aliases", "LOCALAPPDATA", ("Microsoft", "WindowsApps")),
        ("user_start_menu", "APPDATA", ("Microsoft", "Windows", "Start Menu", "Programs")),
        ("all_users_start_menu", "PROGRAMDATA",
         ("Microsoft", "Windows", "Start Menu", "Programs")),
    )
    for label, variable, suffix in locations:
        root = os.environ.get(variable)
        if not root or not Path(root).is_absolute():
            checks.append(label + "_root_unavailable")
            continue
        folder = Path(root).joinpath(*suffix)
        try:
            if not folder.is_dir() or folder.is_symlink():
                checks.append(label + "_not_present")
                continue
            checks.append(label)
            children = list(folder.iterdir())
            if len(children) > 800:
                checks.append(label + "_limit_exceeded")
                continue
            for child in children:
                kind = candidate_kind(child.name)
                if not kind or child.is_symlink():
                    continue
                if child.is_dir() or child.suffix.casefold() in {".exe", ".lnk", ".url"}:
                    candidates.append({"scope": label, "kind": kind,
                                       "signal": "filename_only"})
        except (OSError, PermissionError):
            checks.append(label + "_not_readable")
    return candidates, checks


def _console_username_matches_runner() -> bool | None:
    """Compare Windows user names internally; emit only an equality flag."""
    if os.name != "nt":
        return None
    try:
        kernel = ctypes.windll.kernel32
        kernel.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
        console = int(kernel.WTSGetActiveConsoleSessionId())
        if console == 0xFFFFFFFF:
            return None
        library = ctypes.windll.wtsapi32
        query = library.WTSQuerySessionInformationW
        query.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        library.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        library.WTSFreeMemory.restype = None
        buffer, length = ctypes.c_void_p(), wintypes.DWORD()
        # WTSUserName = 5; only the active console is queried.
        if not query(None, console, 5, ctypes.byref(buffer), ctypes.byref(length)):
            return None
        try:
            observed = ctypes.wstring_at(buffer).casefold() if buffer else ""
        finally:
            if buffer:
                library.WTSFreeMemory(buffer)
        own = ctypes.create_unicode_buffer(256)
        own_size = wintypes.DWORD(len(own))
        get_user = ctypes.windll.advapi32.GetUserNameW
        get_user.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        get_user.restype = wintypes.BOOL
        if not get_user(own, ctypes.byref(own_size)) or not observed:
            return None
        return own.value.casefold() == observed
    except (AttributeError, OSError, ValueError):
        return None



class _ProcessEntry(ctypes.Structure):
    """Win32 PROCESSENTRY32W; only the executable name and session are consulted."""
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _running_candidate_processes() -> tuple[list[dict], bool]:
    """Read process names and console session only; no handles to other processes."""
    if os.name != "nt":
        return [], False
    try:
        kernel = ctypes.windll.kernel32
        snapshot_fn = kernel.CreateToolhelp32Snapshot
        snapshot_fn.argtypes = [wintypes.DWORD, wintypes.DWORD]
        snapshot_fn.restype = wintypes.HANDLE
        # TH32CS_SNAPPROCESS. A read-only snapshot; not a process open.
        snapshot = snapshot_fn(0x00000002, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return [], False
        first = kernel.Process32FirstW
        next_process = kernel.Process32NextW
        first.argtypes = next_process.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
        first.restype = next_process.restype = wintypes.BOOL
        process_session = kernel.ProcessIdToSessionId
        process_session.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        process_session.restype = wintypes.BOOL
        kernel.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        console = int(kernel.WTSGetActiveConsoleSessionId())
        try:
            item = _ProcessEntry()
            item.dwSize = ctypes.sizeof(_ProcessEntry)
            if not first(snapshot, ctypes.byref(item)):
                return [], False
            found, seen = set(), 0
            while True:
                seen += 1
                if seen > 16384:
                    return [], False
                kind = candidate_kind(item.szExeFile)
                if kind:
                    process_sid = wintypes.DWORD()
                    same = (console != 0xFFFFFFFF and
                            bool(process_session(item.th32ProcessID,
                                                 ctypes.byref(process_sid))) and
                            process_sid.value == console)
                    found.add((kind, bool(same)))
                if not next_process(snapshot, ctypes.byref(item)):
                    break
            return ([{"kind": kind, "in_active_console": same,
                      "image_identity_verified": False}
                     for kind, same in sorted(found)]), True
        finally:
            kernel.CloseHandle(snapshot)
    except (AttributeError, OSError, ValueError):
        return [], False

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

    installed, package_checks = _package_candidates(winreg)
    filesystem, folder_checks = _directory_candidates()
    checked.extend(package_checks)
    checked.extend(folder_checks)
    session_id, console_id, console_match = _session_context()
    same_user = _console_username_matches_runner()
    running_processes, processes_enumerated = _running_candidate_processes()
    payload = {
        "schema_version": "chatgpt-startup-audit/v1", "environment": "local/dev",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "host": HOST, "host_confirmed": True,
        "runtime_sha": sha, "github_run_id": run_id,
        "correlation_id": CORRELATION_PREFIX + run_id,
        "runner_session_id": session_id, "active_console_session_id": console_id,
        "runner_matches_active_console": console_match,
        "runner_account_matches_console_username": same_user,
        "installation_candidates": installed + filesystem,
        "running_candidate_processes": running_processes,
        "process_snapshot_valid": processes_enumerated,
        "candidate_name_families": sorted({item["kind"] for item in installed + filesystem}),
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
