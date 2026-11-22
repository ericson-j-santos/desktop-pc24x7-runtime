#!/usr/bin/env python3
"""Read-only PASS-001 UAC session diagnostic for the RP23OGS Windows Gateway.

Does not open a desktop, issue UAC prompts, modify sessions, or read identities,
credentials, screen contents, or private configuration. Never authorizes install.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import socket
from ctypes import wintypes

TARGET = "DESKTOP-RP23OGS"
CONTRACT = "pass001-rp23ogs-uac-session-readonly-v1"
WTS_ACTIVE = 0
WTS_CONNECT_STATE = 8
NO_CONSOLE = 0xFFFFFFFF
UOI_FLAGS = 1
WSF_VISIBLE = 1


class ProbeBlocked(RuntimeError):
    pass


def validate_host(*, hostname: str, system: str, machine: str) -> None:
    if hostname.upper() != TARGET or system != "Windows" or machine.upper() not in {"AMD64", "X86_64"}:
        raise ProbeBlocked("HOST_OR_PLATFORM_DENIED")


def query_session_facts() -> dict[str, object]:
    """Inspect current process vs. the physical console, without user names."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    user = ctypes.WinDLL("user32", use_last_error=True)
    wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    kernel.GetCurrentProcessId.argtypes = []
    kernel.GetCurrentProcessId.restype = wintypes.DWORD
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel.WTSGetActiveConsoleSessionId.argtypes = []
    kernel.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                                                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    wts.WTSFreeMemory.restype = None
    user.GetProcessWindowStation.argtypes = []
    user.GetProcessWindowStation.restype = wintypes.HANDLE
    user.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                               wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    user.GetUserObjectInformationW.restype = wintypes.BOOL

    proc_session = wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId(), ctypes.byref(proc_session)):
        raise ProbeBlocked("PROCESS_SESSION_UNAVAILABLE")
    console_id = int(kernel.WTSGetActiveConsoleSessionId())
    console_session_present = console_id != NO_CONSOLE
    console_active = False
    if console_session_present:
        buf = ctypes.c_void_p()
        length = wintypes.DWORD()
        try:
            ok = wts.WTSQuerySessionInformationW(None, console_id, WTS_CONNECT_STATE,
                                                 ctypes.byref(buf), ctypes.byref(length))
            if ok and buf and length.value >= ctypes.sizeof(wintypes.DWORD):
                state = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
                console_active = state == WTS_ACTIVE
        finally:
            if buf:
                wts.WTSFreeMemory(buf)
    class FLAGS(ctypes.Structure):
        _fields_ = [("inherit", wintypes.BOOL), ("reserved", wintypes.BOOL),
                    ("flags", wintypes.DWORD)]
    station_visible = False
    handle = user.GetProcessWindowStation()
    if handle:
        state = FLAGS()
        needed = wintypes.DWORD()
        if user.GetUserObjectInformationW(handle, UOI_FLAGS, ctypes.byref(state),
                                          ctypes.sizeof(state), ctypes.byref(needed)):
            station_visible = bool(state.flags & WSF_VISIBLE)
    return {
        "process_session_id": int(proc_session.value),
        "console_session_id": console_id if console_session_present else None,
        "active_console_session": console_active,
        "window_station_visible": station_visible,
    }


def classify(facts: dict[str, object]) -> dict[str, object]:
    process = facts["process_session_id"]
    console = facts["console_session_id"]
    same_session = console is not None and process == console
    viable = bool(same_session and facts["active_console_session"] and facts["window_station_visible"])
    return {
        "contract": CONTRACT,
        "host": TARGET,
        "process_session_id": process,
        "console_session_id": console,
        "same_session_as_active_console": same_session,
        "active_console_session": facts["active_console_session"],
        "window_station_visible": facts["window_station_visible"],
        "interactive_uac_ready_for_this_process": viable,
        "result": "INTERACTIVE_PROCESS_CONTEXT_POSSIBLE_NOT_UAC_PROVEN" if viable
                  else "INTERACTIVE_UAC_NOT_PROVEN_FROM_GATEWAY_PROCESS",
        "installation_executed": False,
        "uac_prompt_sent": False,
        "credentials_read": False,
    }


def main() -> int:
    try:
        validate_host(hostname=socket.gethostname(), system=platform.system(), machine=platform.machine())
        data = classify(query_session_facts())
    except (ProbeBlocked, OSError, AttributeError) as exc:
        reason = str(exc) if isinstance(exc, ProbeBlocked) else "WINDOWS_SESSION_READ_UNAVAILABLE"
        data = {"contract": CONTRACT, "result": "BLOCKED", "reason": reason,
                "installation_executed": False}
        print(json.dumps(data, sort_keys=True))
        return 20
    print(json.dumps(data, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
