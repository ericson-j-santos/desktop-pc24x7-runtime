#!/usr/bin/env python3
"""Read-only, redacted Windows Installer event check for prior PASS-001 UAC attempt.

Only emits event IDs/timestamps, never event messages, user identities, paths or
credentials. Does not execute an installer, elevate or interact with Windows UI.
"""
from __future__ import annotations

import ctypes
import json
import platform
import socket
from ctypes import wintypes
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

HOST = "DESKTOP-RP23OGS"
CONTRACT = "pass001-msi-event-diagnostic-readonly-v1"
START = datetime.fromisoformat("2026-11-22T15:22:00+00:00")
END = datetime.fromisoformat("2026-11-22T15:29:00+00:00")
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
ERROR_NO_MORE_ITEMS = 259
ERROR_INSUFFICIENT_BUFFER = 122


class ProbeBlocked(RuntimeError):
    pass


def ensure_target(host: str, system: str, machine: str) -> None:
    if host.upper() != HOST or system != "Windows" or machine.upper() not in {"AMD64", "X86_64"}:
        raise ProbeBlocked("HOST_OR_PLATFORM_DENIED")


def parse_system_xml(xml: str) -> dict[str, object]:
    """Parse only System metadata, discarding possibly sensitive EventData."""
    try:
        root = ET.fromstring(xml)
        sys_node = root.find(NS + "System")
        if sys_node is None:
            raise ValueError("missing")
        provider = sys_node.find(NS + "Provider")
        eventid = sys_node.find(NS + "EventID")
        created = sys_node.find(NS + "TimeCreated")
        if provider is None or provider.get("Name") != "MsiInstaller":
            raise ValueError("wrong provider")
        if eventid is None or eventid.text is None or not eventid.text.isdecimal():
            raise ValueError("event ID")
        if created is None or not created.get("SystemTime"):
            raise ValueError("event time")
        t = datetime.fromisoformat(created.attrib["SystemTime"].replace("Z", "+00:00"))
        if t.tzinfo is None:
            raise ValueError("timezone")
        return {"event_id": int(eventid.text), "utc": t.astimezone(timezone.utc).isoformat()}
    except (ET.ParseError, TypeError, ValueError, OverflowError) as exc:
        raise ProbeBlocked("EVENT_XML_INVALID") from None


def collect_msi_events() -> list[dict[str, object]]:
    """Windows EvtQuery for recent MsiInstaller events; no subprocesses or UI."""
    evt = ctypes.WinDLL("wevtapi", use_last_error=True)
    evt.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    evt.EvtQuery.restype = wintypes.HANDLE
    evt.EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
                            wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    evt.EvtNext.restype = wintypes.BOOL
    evt.EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                              ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    evt.EvtRender.restype = wintypes.BOOL
    evt.EvtClose.argtypes = [wintypes.HANDLE]
    evt.EvtClose.restype = wintypes.BOOL
    # Latest 24h, recent-first; do not enumerate unrelated messages.
    q = "*[System[Provider[@Name='MsiInstaller'] and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
    handle = evt.EvtQuery(None, "Application", q, 1 | 0x200)
    if not handle:
        raise ProbeBlocked("WINDOWS_EVENT_QUERY_UNAVAILABLE")
    matched: list[dict[str, object]] = []
    try:
        for _ in range(256):
            events = (wintypes.HANDLE * 1)()
            returned = wintypes.DWORD()
            if not evt.EvtNext(handle, 1, events, 1000, 0, ctypes.byref(returned)):
                if ctypes.get_last_error() == ERROR_NO_MORE_ITEMS:
                    break
                raise ProbeBlocked("WINDOWS_EVENT_READ_UNAVAILABLE")
            if not returned.value:
                break
            one = events[0]
            try:
                used = wintypes.DWORD()
                count = wintypes.DWORD()
                if evt.EvtRender(None, one, 1, 0, None, ctypes.byref(used), ctypes.byref(count)):
                    raise ProbeBlocked("WINDOWS_EVENT_RENDER_UNEXPECTED")
                if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER or not 2 <= used.value <= 262144:
                    raise ProbeBlocked("WINDOWS_EVENT_RENDER_UNAVAILABLE")
                buf = ctypes.create_string_buffer(used.value)
                if not evt.EvtRender(None, one, 1, used.value, buf,
                                     ctypes.byref(used), ctypes.byref(count)):
                    raise ProbeBlocked("WINDOWS_EVENT_RENDER_UNAVAILABLE")
                row = parse_system_xml(buf.raw[:used.value].decode("utf-16-le").rstrip("\x00"))
                t = datetime.fromisoformat(str(row["utc"]))
                if START <= t <= END:
                    matched.append(row)
                if t < START:  # Reverse chronological query.
                    break
            finally:
                evt.EvtClose(one)
    finally:
        evt.EvtClose(handle)
    return matched


def make_result(events: list[dict[str, object]]) -> dict[str, object]:
    return {"contract": CONTRACT, "host": HOST,
            "historical_window_utc": [START.isoformat(), END.isoformat()],
            "msi_installer_event_count": len(events),
            "events": events,
            "result": "MSI_INSTALLER_EVENTS_IN_WINDOW" if events else "NO_MSI_INSTALLER_EVENTS_IN_WINDOW",
            "uac_prompt_status": "NOT_OBSERVED",
            "installation_executed": False,
            "session_changed": False}


def main() -> int:
    try:
        ensure_target(socket.gethostname(), platform.system(), platform.machine())
        result = make_result(collect_msi_events())
    except (ProbeBlocked, OSError, AttributeError, UnicodeError) as exc:
        reason = str(exc) if isinstance(exc, ProbeBlocked) else "EVENT_PROVIDER_READ_UNAVAILABLE"
        print(json.dumps({"contract": CONTRACT, "result": "BLOCKED", "reason": reason,
                          "installation_executed": False}, sort_keys=True))
        return 20
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
