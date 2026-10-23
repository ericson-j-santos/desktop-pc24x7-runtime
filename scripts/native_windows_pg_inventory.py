#!/usr/bin/env python3
"""Fixed Windows metadata inventory. No database connection or Linux launch.

Run only through the repository's governed manual workflow. This is discovery,
not qualification: neither an absent registration nor a fixed disk proves
absence of a database, durability, backup, restart safety or service readiness.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import re
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HOST = "DESKTOP-PDQK954"
EXPECTED_RUNNER = "DESKTOP-PDQK954-runtime"
EXPECTED_REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
OUTPUT = Path("artifacts/native-pg-inventory/evidence.json")
PORTS = (5432, 8000, 15432, 18210)
MAJORS = tuple(range(10, 19))
COMPONENTS = ("postgres", "pg_ctl", "psql")
MAX_ROWS = 4096
MAX_BYTES = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}")
PG_SERVICE = re.compile(r"postgres(?:ql)?(?:[-_].*)?", re.IGNORECASE)
STATES = {1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
          5: "continue_pending", 6: "pause_pending", 7: "paused"}
CI_KEYS = ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_SHA", "RULES_SHA",
           "RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "GITHUB_RUN_ID",
           "GITHUB_RUN_ATTEMPT", "GITHUB_ACTOR", "GITHUB_EVENT_NAME",
           "RUNNER_VERSION_OBSERVED", "RUNNER_RUNTIME_SUPPORTED",
           "RUNNER_REGISTRATION_SUPPORTED", "INVENTORY_SESSION_VALIDATED", "INVENTORY_ADMITTED_AT")


class InventoryBlocked(Exception):
    """Constant failure code only; never include OS messages or raw metadata."""


def provenance(env: dict, host: str, platform: str) -> dict:
    try:
        admitted = datetime.fromisoformat(env.get("INVENTORY_ADMITTED_AT", "").replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - admitted).total_seconds()
    except (ValueError, TypeError):
        raise InventoryBlocked("ADMISSION_EXPIRED") from None
    valid = (
        0 <= age <= 300
        and platform == "win32"
        and host.casefold() == EXPECTED_HOST.casefold()
        and env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_REPOSITORY") == EXPECTED_REPOSITORY
        and env.get("RUNNER_NAME") == EXPECTED_RUNNER
        and env.get("RUNNER_OS") == "Windows" and env.get("RUNNER_ARCH") == "X64"
        and env.get("GITHUB_ACTOR") == "ericson-j-santos"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_RUN_ATTEMPT") == "1"
        and re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", "")) is not None
        and SHA.fullmatch(env.get("GITHUB_SHA", "")) is not None
        and SHA.fullmatch(env.get("RULES_SHA", "")) is not None
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",
                         env.get("RUNNER_VERSION_OBSERVED", "")) is not None
        and env.get("RUNNER_RUNTIME_SUPPORTED") == "true"
        and env.get("RUNNER_REGISTRATION_SUPPORTED") == "true"
        and env.get("INVENTORY_SESSION_VALIDATED") == "true"
    )
    if not valid:
        raise InventoryBlocked("PROVENANCE_REJECTED")
    # These assertions are not a substitute for the external Gateway snapshot.
    return {"host_alias": "authorized-primary", "source_sha": env["GITHUB_SHA"],
            "rules_sha": env["RULES_SHA"], "run_id": env["GITHUB_RUN_ID"],
            "correlation_id": "dedicated-runner-" + env["GITHUB_RUN_ID"] + "-1",
            "run_attempt": 1, "runner_version": env["RUNNER_VERSION_OBSERVED"]}


def bounded_int(value, maximum=2**63 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise InventoryBlocked("INVALID_METADATA")
    return value


def bind_class(address: bytes) -> str:
    ip = ipaddress.ip_address(address)
    if ip.is_unspecified:
        return "wildcard"
    if ip.is_loopback or (getattr(ip, "ipv4_mapped", None) and ip.ipv4_mapped.is_loopback):
        return "loopback"
    return "other"


def parse_tcp_table(raw: bytes, family: int) -> list[dict]:
    # Windows DWORD is always 32-bit, including 64-bit Windows.
    if family not in (2, 23) or len(raw) < 4 or len(raw) > MAX_BYTES:
        raise InventoryBlocked("INVALID_TCP_TABLE")
    count = struct.unpack_from("<I", raw)[0]
    width = 24 if family == 2 else 56
    if count > MAX_ROWS or 4 + count * width > len(raw):
        raise InventoryBlocked("INVALID_TCP_TABLE")
    found = set()
    for index in range(count):
        row = raw[4 + index * width:4 + (index + 1) * width]
        if family == 2:
            state = struct.unpack_from("<I", row)[0]
            address, port_bytes = row[4:8], row[8:10]
        else:
            state = struct.unpack_from("<I", row, 48)[0]
            address, port_bytes = row[:16], row[20:22]
        port = int.from_bytes(port_bytes, "big")
        if state == 2 and port in PORTS:
            found.add((port, "ipv4" if family == 2 else "ipv6", bind_class(address)))
    return [{"port": p, "family": f, "bind": b} for p, f, b in sorted(found)]


def safe_section(call):
    try:
        return {"status": "measured", "items": call()}
    except PermissionError:
        return {"status": "unavailable", "reason": "access_denied", "items": None}
    except (OSError, ValueError, InventoryBlocked):
        return {"status": "unavailable", "reason": "read_failed", "items": None}


class WindowsMetadata:
    """Only read-only Win32 APIs and bounded registry/file metadata reads."""

    def __init__(self):
        if sys.platform != "win32":
            raise InventoryBlocked("WINDOWS_REQUIRED")
        import winreg
        self.reg = winreg
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x00000800)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True, winmode=0x00000800)
        self.iphelper = ctypes.WinDLL("iphlpapi", use_last_error=True, winmode=0x00000800)
        self.version = ctypes.WinDLL("version", use_last_error=True, winmode=0x00000800)

    @staticmethod
    def fn(dll, name, returns, arguments):
        function = getattr(dll, name)
        function.restype, function.argtypes = returns, arguments
        return function

    def keys(self, root, path, limit=MAX_ROWS):
        reg = self.reg
        with reg.OpenKey(root, path, 0, reg.KEY_READ) as key:
            count = reg.QueryInfoKey(key)[0]
            if count > limit:
                raise InventoryBlocked("REGISTRY_LIMIT")
            return sorted(reg.EnumKey(key, i) for i in range(count))

    def os_version(self):
        version = sys.getwindowsversion()
        return [{"major": version.major, "minor": version.minor, "build": version.build}]

    def wsl(self):
        # HKCU belongs to the runner account, not all interactive user profiles.
        # Do not call WSL or access distro VHDs, filesystems or configuration.
        reg = self.reg
        base = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
        try:
            keys = self.keys(reg.HKEY_CURRENT_USER, base, 64)
        except FileNotFoundError:
            return []
        result = []
        for key in keys:
            with reg.OpenKey(reg.HKEY_CURRENT_USER, base + "\\" + key, 0, reg.KEY_READ) as child:
                try:
                    number, _ = reg.QueryValueEx(child, "Version")
                except FileNotFoundError:
                    number = None
            result.append({"alias": "distro-" + str(len(result) + 1),
                           "wsl_version": number if type(number) is int and number in (1, 2) else None,
                           "state": "unknown"})
        return result

    def pg_services(self):
        names = [n for n in self.keys(self.reg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services")
                 if PG_SERVICE.fullmatch(n)]
        if len(names) > 64:
            raise InventoryBlocked("SERVICE_LIMIT")
        open_manager = self.fn(self.advapi, "OpenSCManagerW", ctypes.c_void_p,
                               [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32])
        open_service = self.fn(self.advapi, "OpenServiceW", ctypes.c_void_p,
                               [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32])
        query = self.fn(self.advapi, "QueryServiceStatusEx", ctypes.c_int,
                       [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)])
        close = self.fn(self.advapi, "CloseServiceHandle", ctypes.c_int, [ctypes.c_void_p])
        manager = open_manager(None, None, 0x0001)  # SC_MANAGER_CONNECT
        if not manager:
            raise ctypes.WinError(ctypes.get_last_error())
        result = []
        try:
            for name in names:
                handle = open_service(manager, name, 0x0004)  # SERVICE_QUERY_STATUS only
                if not handle:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    status = (ctypes.c_uint32 * 9)()
                    needed = ctypes.c_uint32()
                    if not query(handle, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(needed)):
                        raise ctypes.WinError(ctypes.get_last_error())
                    result.append({"alias": "pg-service-" + str(len(result) + 1),
                                   "state": STATES.get(status[1], "unknown")})
                finally:
                    close(handle)
        finally:
            close(manager)
        return result

    @staticmethod
    def safe_metadata_path(path: Path):
        if not path.is_absolute() or str(path).startswith("\\\\"):
            raise InventoryBlocked("PATH_REJECTED")
        for part in reversed((path,) + tuple(path.parents)):
            entry = part.lstat()
            if getattr(entry, "st_file_attributes", 0) & 0x400 or part.is_symlink():
                raise InventoryBlocked("REPARSE_REJECTED")

    def file_version(self, path: Path):
        self.safe_metadata_path(path)
        size_fn = self.fn(self.version, "GetFileVersionInfoSizeW", ctypes.c_uint32,
                          [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)])
        get_fn = self.fn(self.version, "GetFileVersionInfoW", ctypes.c_int,
                         [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p])
        value_fn = self.fn(self.version, "VerQueryValueW", ctypes.c_int,
                           [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(ctypes.c_uint32)])
        ignored = ctypes.c_uint32()
        size = size_fn(str(path), ctypes.byref(ignored))
        if not 52 <= size <= MAX_BYTES:
            raise InventoryBlocked("VERSION_RESOURCE_INVALID")
        data = ctypes.create_string_buffer(size)
        pointer, length = ctypes.c_void_p(), ctypes.c_uint32()
        if not get_fn(str(path), 0, size, data) or not value_fn(data, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            raise InventoryBlocked("VERSION_RESOURCE_INVALID")
        if length.value < 52 or length.value > size or pointer.value is None:
            raise InventoryBlocked("VERSION_RESOURCE_INVALID")
        start = ctypes.addressof(data)
        if not start <= pointer.value <= start + size - 52:
            raise InventoryBlocked("VERSION_RESOURCE_INVALID")
        fixed = (ctypes.c_uint32 * 13).from_address(pointer.value)
        if fixed[0] != 0xFEEF04BD:
            raise InventoryBlocked("VERSION_RESOURCE_INVALID")
        return ".".join(str(v) for v in
                        (fixed[2] >> 16, fixed[2] & 65535, fixed[3] >> 16, fixed[3] & 65535))

    def pg_binaries(self):
        # Fixed official installation layout, no PATH search or custom directories.
        reg = self.reg
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion", 0,
                         reg.KEY_READ | reg.KEY_WOW64_64KEY) as key:
            folder, kind = reg.QueryValueEx(key, "ProgramFilesDir")
        if kind != reg.REG_SZ or not isinstance(folder, str) or len(folder) > 260:
            raise InventoryBlocked("PROGRAM_FILES_INVALID")
        result = []
        for major in MAJORS:
            for component in COMPONENTS:
                candidate = Path(folder) / "PostgreSQL" / str(major) / "bin" / (component + ".exe")
                try:
                    version = self.file_version(candidate)
                except FileNotFoundError:
                    continue
                result.append({"layout_major": major, "component": component, "file_version": version})
        return result

    def fixed_disks(self):
        drives = self.fn(self.kernel, "GetLogicalDrives", ctypes.c_uint32, [])()
        if drives == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        drive_type = self.fn(self.kernel, "GetDriveTypeW", ctypes.c_uint32, [ctypes.c_wchar_p])
        free = self.fn(self.kernel, "GetDiskFreeSpaceExW", ctypes.c_int,
                       [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint64),
                        ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)])
        result = []
        for index in range(26):
            if not drives & (1 << index):
                continue
            root = chr(65 + index) + ":\\"
            if drive_type(root) != 3:  # DRIVE_FIXED only; never query network disks
                continue
            available, total, unused = ctypes.c_uint64(), ctypes.c_uint64(), ctypes.c_uint64()
            if not free(root, ctypes.byref(available), ctypes.byref(total), ctypes.byref(unused)):
                raise ctypes.WinError(ctypes.get_last_error())
            result.append({"alias": "fixed-volume-" + str(len(result) + 1),
                           "size_gib_floor": total.value // 2**30,
                           "available_gib_floor": available.value // 2**30})
        return result

    def tcp(self):
        query = self.fn(self.iphelper, "GetExtendedTcpTable", ctypes.c_uint32,
                        [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                         ctypes.c_int, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32])
        result = []
        for family in (2, 23):
            size = ctypes.c_uint32()
            code = query(None, ctypes.byref(size), False, family, 3, 0)
            if code not in (0, 122) or not 4 <= size.value <= MAX_BYTES:
                raise InventoryBlocked("TCP_QUERY_FAILED")
            data = ctypes.create_string_buffer(size.value)
            code = query(data, ctypes.byref(size), False, family, 3, 0)
            # Concurrent growth is unavailable, not an unbounded retry or empty list.
            if code != 0 or size.value > len(data):
                raise InventoryBlocked("TCP_QUERY_FAILED")
            result.extend(parse_tcp_table(data.raw[:size.value], family))
        return result


def report(env, host, platform, backend_factory=WindowsMetadata):
    identity = provenance(env, host, platform)  # before any physical metadata API
    backend = backend_factory()
    sections = {name: safe_section(getattr(backend, method)) for name, method in
                (("os", "os_version"), ("wsl", "wsl"), ("pg_services", "pg_services"),
                 ("pg_binaries", "pg_binaries"), ("fixed_disks", "fixed_disks"),
                 ("candidate_tcp_listeners", "tcp"))}
    result = {"contract": "native-pg-inventory-v1", **identity,
              "status": "measured" if all(s["status"] == "measured" for s in sections.values()) else "partial",
              "sections": sections,
              "scope": {"wsl": "current_runner_hkcu_only",
                        "services": "postgres_or_postgresql_name_prefix_only",
                        "binaries": "program_files_postgresql_10_through_18_only",
                        "tcp_ports": list(PORTS), "tcp_owners_collected": False},
              "linux_started": False, "database_connected": False,
              "database_contents_read": False, "application_environment_read": False,
              "credentials_read": False, "configuration_changed": False,
              "systemd_verified": False, "storage_durability_verified": False,
              "backup_restore_verified": False, "restart_verified": False,
              "database_target_qualified": False, "ready_for_installation": False}
    validate_report(result)
    return result


def validate_report(value):
    # Backend output is not trusted as a serialization contract.
    expected_keys = {
        "contract", "host_alias", "source_sha", "rules_sha", "run_id", "run_attempt",
        "runner_version", "correlation_id", "status", "sections", "scope", "linux_started",
        "database_connected", "database_contents_read", "application_environment_read",
        "credentials_read", "configuration_changed", "systemd_verified",
        "storage_durability_verified", "backup_restore_verified", "restart_verified",
        "database_target_qualified", "ready_for_installation",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise InventoryBlocked("REPORT_SCHEMA_REJECTED")
    sections = value["sections"]
    schemas = {
        "os": {"major": (0, 100), "minor": (0, 100), "build": (0, 1000000)},
        "wsl": {"alias": r"distro-[1-9][0-9]?", "wsl_version": (None, 1, 2), "state": ("unknown",)},
        "pg_services": {"alias": r"pg-service-[1-9][0-9]?", "state": tuple(STATES.values()) + ("unknown",)},
        "pg_binaries": {"layout_major": MAJORS, "component": COMPONENTS,
                        "file_version": r"[0-9]{1,5}(\.[0-9]{1,5}){3}"},
        "fixed_disks": {"alias": r"fixed-volume-[1-9][0-9]?",
                        "size_gib_floor": (0, 2**32), "available_gib_floor": (0, 2**32)},
        "candidate_tcp_listeners": {"port": PORTS, "family": ("ipv4", "ipv6"),
                                    "bind": ("loopback", "wildcard", "other")},
    }
    if set(sections) != set(schemas):
        raise InventoryBlocked("REPORT_SCHEMA_REJECTED")
    for name, section in sections.items():
        if section["status"] == "unavailable":
            if set(section) != {"status", "reason", "items"} or section["items"] is not None or section["reason"] not in ("access_denied", "read_failed"):
                raise InventoryBlocked("REPORT_SCHEMA_REJECTED")
            continue
        if set(section) != {"status", "items"} or section["status"] != "measured":
            raise InventoryBlocked("REPORT_SCHEMA_REJECTED")
        if not isinstance(section["items"], list) or len(section["items"]) > 64:
            raise InventoryBlocked("REPORT_SCHEMA_REJECTED")
        for row in section["items"]:
            schema = schemas[name]
            if not isinstance(row, dict) or set(row) != set(schema):
                raise InventoryBlocked("REPORT_SCHEMA_REJECTED")
            for key, rule in schema.items():
                data = row[key]
                if isinstance(rule, str):
                    valid = isinstance(data, str) and re.fullmatch(rule, data) is not None
                elif key in ("major", "minor", "build", "size_gib_floor", "available_gib_floor"):
                    valid = type(data) is int and rule[0] <= data <= rule[1]
                else:
                    valid = data in rule and (type(data) is int if isinstance(rule[0], int) else True)
                    if key == "wsl_version":
                        valid = data is None or type(data) is int and data in (1, 2)
                if not valid:
                    raise InventoryBlocked("REPORT_SCHEMA_REJECTED")
    if len(json.dumps(value)) > 32768:
        raise InventoryBlocked("REPORT_TOO_LARGE")


def write_report(value):
    # No caller-provided output path; no overwrite, symlink or junction following.
    root = Path.cwd()
    if root.resolve() != root:
        raise InventoryBlocked("OUTPUT_ROOT_REJECTED")
    parent = root
    for component in OUTPUT.parent.parts:
        parent = parent / component
        try:
            parent.mkdir()
        except FileExistsError:
            pass
        metadata = parent.lstat()
        if not parent.is_dir() or parent.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise InventoryBlocked("OUTPUT_PARENT_REJECTED")
    with (root / OUTPUT).open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    try:
        if len(sys.argv) != 1:
            raise InventoryBlocked("ARGUMENTS_REJECTED")
        env = {name: os.environ.get(name, "") for name in CI_KEYS}
        evidence = report(env, socket.gethostname(), sys.platform)
        write_report(evidence)
    except (InventoryBlocked, OSError, ValueError, KeyError, TypeError):
        print('{"contract":"native-pg-inventory-v1","status":"blocked"}')
        return 3
    # The allowlisted receipt is recoverable from job logs without billed artifact storage.
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["status"] == "measured" else 2


if __name__ == "__main__":
    raise SystemExit(main())
