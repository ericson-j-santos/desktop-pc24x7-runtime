#!/usr/bin/env python3
"""Fixed metadata attribution for TCP 5432 only; never connect to a database.

Image basenames are hints, not authenticated identities or protocol proof.
Only sanitized JSON is emitted. No WSL, service, process or network mutation.
"""
from __future__ import annotations

import ctypes
import importlib.util
import json
import ntpath
import os
import re
import socket
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Explicit sibling loading also works with isolated portable Python _pth files.
_SPEC = importlib.util.spec_from_file_location(
    "_native_pg_inventory_contract", Path(__file__).with_name("native_windows_pg_inventory.py"),
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("INVENTORY_CONTRACT_UNAVAILABLE")
base = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(base)

PORT = 5432
MAX_OWNERS = 16
MAX_ITEMS = 64
# Conservative: directory/reparse/offline/EA-or-recall-enumeration/recall-data.
REJECTED_FILE_ATTRIBUTES = 0x10 | 0x400 | 0x1000 | 0x40000 | 0x400000
HINTS = ("postgres-image", "wsl-related-image", "container-related-image",
         "windows-host-image", "other-image", "unknown")
ATTRIBUTIONS = ("stable_metadata", "access_denied", "process_unavailable", "process_changed")
FALSE_FIELDS = ("image_identity_verified", "database_connected", "database_contents_read",
                "application_environment_read", "configuration_changed",
                "linux_started", "storage_durability_verified", "backup_restore_verified",
                "database_target_qualified", "ready_for_installation")
SCOPE = {
    "port": PORT,
    "tcp_snapshot": "all_listeners_transient_then_5432_filter",
    "process_query": "query_limited_information_only_for_5432_pids",
    "process_snapshot": "two_bounded_metadata_reads_not_atomic",
    "output": "sanitized_job_log_only",
    "classification_basis": "basename_allowlist_only",
    "legacy_receipts": "two_fixed_json_files_current_runner_profile_only",
    "receipt_input": "bounded_whole_json_transient_then_allowlist_projection",
    "credential_files_opened": False,
    "backup_files_opened": False,
    "raw_pid_emitted": False,
    "raw_address_emitted": False,
    "image_path_emitted": False,
    "commandline_read": False,
    "service_registry_read": False,
}



RECEIPT_LIMIT = 65536
RECEIPTS = (
    ("legacy-e2e", "e2e-last.json", "todo-global-pc24x7-live-e2e"),
    ("legacy-resilience", "resilience-last.json", "todo-global-pc24x7-resilience"),
)


def strict_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def reject_constant(_):
    raise ValueError("NONFINITE_JSON")


def nested(data, *keys):
    for key in keys:
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def nullable_boolean(value):
    if value is not None and type(value) is not bool:
        raise ValueError("BOOLEAN_REQUIRED")
    return value


def sanitize_receipt(raw, alias, contract):
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= RECEIPT_LIMIT:
        raise ValueError("RECEIPT_SIZE")
    data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=strict_pairs,
                      parse_constant=reject_constant)
    if not isinstance(data, dict) or data.get("contract") != contract:
        raise ValueError("RECEIPT_CONTRACT")
    stamp = data.get("generated_at")
    if not isinstance(stamp, str) or len(stamp) > 40:
        raise ValueError("RECEIPT_TIMESTAMP")
    timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("RECEIPT_TIMEZONE")
    if not 2000 <= timestamp.year <= 2100:
        raise ValueError("RECEIPT_TIMESTAMP_RANGE")
    try:
        normalized = timestamp.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ValueError("RECEIPT_TIMESTAMP_RANGE") from None
    if normalized > datetime.now(timezone.utc):
        raise ValueError("RECEIPT_FUTURE_TIMESTAMP")
    result = {"alias": alias, "status": "parsed", "contract": contract,
              "generated_date_utc": normalized.date().isoformat(),
              "historical_ready": nullable_boolean(data.get("ready"))}
    if alias == "legacy-e2e":
        for key in ("sql_event_readback", "sql_continuation_readback", "negative_control_passed"):
            result[key] = nullable_boolean(data.get(key))
    else:
        result["restart_persistent"] = nullable_boolean(nested(data, "restart", "persistent"))
        result["restore_verified"] = nullable_boolean(nested(data, "backup_restore", "restore_verified"))
        size = nested(data, "backup_restore", "backup_size")
        if size is not None and (type(size) is not int or not 0 <= size <= 2**63 - 1):
            raise ValueError("BACKUP_SIZE")
        result["recorded_backup_bytes"] = size
        digest = nested(data, "backup_restore", "backup_sha256")
        result["backup_hash_recorded"] = isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        # Never resolve, stat, open or emit backup_file from the receipt.
    return result


def receipt_projection(reader):
    result = []
    for alias, filename, contract in RECEIPTS:
        try:
            result.append(sanitize_receipt(reader(filename), alias, contract))
        except FileNotFoundError:
            result.append({"alias": alias, "status": "missing"})
        except PermissionError:
            result.append({"alias": alias, "status": "access_denied"})
        except (OSError, ValueError, TypeError, RecursionError, OverflowError, base.InventoryBlocked):
            result.append({"alias": alias, "status": "unavailable_or_invalid"})
    return result


def image_hint(path):
    if not isinstance(path, str) or not 1 <= len(path) <= 32768 or "\0" in path:
        raise base.InventoryBlocked("IMAGE_METADATA_INVALID")
    name = ntpath.basename(path).casefold()
    if name == "postgres.exe":
        return "postgres-image"
    if name in ("wslhost.exe", "wslrelay.exe", "wslservice.exe"):
        return "wsl-related-image"
    if name in ("com.docker.backend.exe", "docker-proxy.exe"):
        return "container-related-image"
    if name in ("svchost.exe", "services.exe"):
        return "windows-host-image"
    return "other-image"


def parse_owners(raw, family):
    if family not in (2, 23) or len(raw) < 4 or len(raw) > base.MAX_BYTES:
        raise base.InventoryBlocked("INVALID_TCP_TABLE")
    count = struct.unpack_from("<I", raw)[0]
    width = 24 if family == 2 else 56
    if count > base.MAX_ROWS or 4 + count * width > len(raw):
        raise base.InventoryBlocked("INVALID_TCP_TABLE")
    found = set()
    for index in range(count):
        row = raw[4 + index * width:4 + (index + 1) * width]
        if family == 2:
            state = struct.unpack_from("<I", row)[0]
            address, port_bytes, pid_offset = row[4:8], row[8:10], 20
        else:
            state = struct.unpack_from("<I", row, 48)[0]
            address, port_bytes, pid_offset = row[:16], row[20:22], 52
        if state == 2 and int.from_bytes(port_bytes, "big") == PORT:
            pid = struct.unpack_from("<I", row, pid_offset)[0]
            found.add(("ipv4" if family == 2 else "ipv6", base.bind_class(address), pid))
    if len(found) > MAX_ITEMS or len({row[2] for row in found}) > MAX_OWNERS:
        raise base.InventoryBlocked("OWNER_LIMIT")
    return sorted(found)


class WindowsOwnerMetadata(base.WindowsMetadata):
    def read_legacy_receipt(self, filename):
        if filename not in {item[1] for item in RECEIPTS}:
            raise base.InventoryBlocked("RECEIPT_PATH_REJECTED")
        shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x00000800)
        ole = ctypes.WinDLL("ole32", use_last_error=True, winmode=0x00000800)
        known = self.fn(shell, "SHGetKnownFolderPath", ctypes.c_int32,
                        [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_void_p)])
        release = self.fn(ole, "CoTaskMemFree", None, [ctypes.c_void_p])
        folder_id = (ctypes.c_ubyte * 16).from_buffer_copy(
            uuid.UUID("F1B32785-6FBA-4FCF-9D55-7B8E7F157091").bytes_le)
        pointer = ctypes.c_void_p()
        try:
            # KF_FLAG_DONT_VERIFY; no creation and current-user token only.
            code = known(ctypes.byref(folder_id), 0x4000, None, ctypes.byref(pointer))
            if code != 0 or not pointer.value:
                raise base.InventoryBlocked("PROFILE_PATH_UNAVAILABLE")
            folder = ctypes.wstring_at(pointer.value)
        finally:
            if pointer.value:
                release(pointer)
        if not 3 <= len(folder) <= 32700 or not ntpath.splitdrive(folder)[0] or folder.startswith("\\\\"):
            raise base.InventoryBlocked("PROFILE_PATH_REJECTED")
        drive_type = self.fn(self.kernel, "GetDriveTypeW", ctypes.c_uint32, [ctypes.c_wchar_p])
        if drive_type(ntpath.splitdrive(folder)[0] + "\\") != 3:
            raise base.InventoryBlocked("PROFILE_NOT_FIXED_VOLUME")
        path = Path(folder) / "ReqSys" / "TodoGlobal24x7" / "evidence" / filename
        base.WindowsMetadata.safe_metadata_path(path)
        attributes = self.fn(self.kernel, "GetFileAttributesW", ctypes.c_uint32, [ctypes.c_wchar_p])
        observed_attributes = attributes(str(path))
        if observed_attributes == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        if observed_attributes & REJECTED_FILE_ATTRIBUTES:
            raise base.InventoryBlocked("RECEIPT_PLACEHOLDER_OR_SPECIAL_FILE")
        create = self.fn(self.kernel, "CreateFileW", ctypes.c_void_p,
                         [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                          ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p])
        info_fn = self.fn(self.kernel, "GetFileInformationByHandle", ctypes.c_int,
                          [ctypes.c_void_p, ctypes.c_void_p])
        final_name = self.fn(self.kernel, "GetFinalPathNameByHandleW", ctypes.c_uint32,
                             [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32])
        read = self.fn(self.kernel, "ReadFile", ctypes.c_int,
                       [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p])
        close = self.fn(self.kernel, "CloseHandle", ctypes.c_int, [ctypes.c_void_p])
        # Read-only, OPEN_EXISTING, OPEN_REPARSE_POINT | OPEN_NO_RECALL.
        # Attributes are checked again after opening. No absolute atomicity claim.
        handle = create(str(path), 0x80000000, 7, None, 3, 0x00300000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            before = (ctypes.c_uint32 * 13)()
            if not info_fn(handle, ctypes.byref(before)):
                raise ctypes.WinError(ctypes.get_last_error())
            size = (before[8] << 32) | before[9]
            if before[0] & REJECTED_FILE_ATTRIBUTES or before[10] != 1 or not 2 <= size <= RECEIPT_LIMIT:
                raise base.InventoryBlocked("RECEIPT_FILE_REJECTED")
            canonical = ctypes.create_unicode_buffer(32768)
            length = final_name(handle, canonical, len(canonical), 0)
            if not 0 < length < len(canonical):
                raise base.InventoryBlocked("RECEIPT_FINAL_PATH_REJECTED")
            observed = canonical.value
            if observed.startswith("\\\\?\\"):
                observed = observed[4:]
            if ntpath.normcase(ntpath.normpath(observed)) != ntpath.normcase(ntpath.normpath(str(path))):
                raise base.InventoryBlocked("RECEIPT_FINAL_PATH_REJECTED")
            data, count = ctypes.create_string_buffer(RECEIPT_LIMIT + 1), ctypes.c_uint32()
            if not read(handle, data, len(data), ctypes.byref(count), None):
                raise ctypes.WinError(ctypes.get_last_error())
            after = (ctypes.c_uint32 * 13)()
            if not info_fn(handle, ctypes.byref(after)):
                raise ctypes.WinError(ctypes.get_last_error())
            stable = (0, 5, 6, 7, 8, 9, 10, 11, 12)
            if count.value != size or any(before[i] != after[i] for i in stable):
                raise base.InventoryBlocked("RECEIPT_CHANGED")
            return data.raw[:count.value]
        finally:
            close(handle)

    def tcp_5432(self):
        query = self.fn(self.iphelper, "GetExtendedTcpTable", ctypes.c_uint32,
                        [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                         ctypes.c_int, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32])
        rows = []
        for family in (2, 23):
            size = ctypes.c_uint32()
            code = query(None, ctypes.byref(size), False, family, 3, 0)
            if code not in (0, 122) or not 4 <= size.value <= base.MAX_BYTES:
                raise base.InventoryBlocked("TCP_QUERY_FAILED")
            data = ctypes.create_string_buffer(size.value)
            code = query(data, ctypes.byref(size), False, family, 3, 0)
            if code != 0 or size.value > len(data):
                raise base.InventoryBlocked("TCP_QUERY_FAILED")
            rows.extend(parse_owners(data.raw[:size.value], family))
        rows = sorted(set(rows))
        if len(rows) > MAX_ITEMS or len({row[2] for row in rows}) > MAX_OWNERS:
            raise base.InventoryBlocked("OWNER_LIMIT")
        return rows

    def process_metadata(self, pid):
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
            raise base.InventoryBlocked("PID_UNAVAILABLE")
        open_process = self.fn(self.kernel, "OpenProcess", ctypes.c_void_p,
                               [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32])
        image = self.fn(self.kernel, "QueryFullProcessImageNameW", ctypes.c_int,
                        [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_uint32)])
        times = self.fn(self.kernel, "GetProcessTimes", ctypes.c_int,
                        [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4)
        close = self.fn(self.kernel, "CloseHandle", ctypes.c_int, [ctypes.c_void_p])
        handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION only
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = ctypes.c_uint32(32768)
            path = ctypes.create_unicode_buffer(size.value)
            if not image(handle, 0, path, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            if not 0 < size.value < len(path):
                raise base.InventoryBlocked("IMAGE_METADATA_TRUNCATED")
            creation, ended, kernel, user = (ctypes.c_uint64() for _ in range(4))
            if not times(handle, ctypes.byref(creation), ctypes.byref(ended),
                         ctypes.byref(kernel), ctypes.byref(user)):
                raise ctypes.WinError(ctypes.get_last_error())
            # The full path and timestamps remain transient; never serialize them.
            return image_hint(path.value), creation.value
        finally:
            close(handle)


def safe_probe(probe, pid):
    try:
        item = probe(pid)
        if (not isinstance(item, tuple) or len(item) != 2 or item[0] not in HINTS[:-1]
                or type(item[1]) is not int or not 0 < item[1] <= 2**64 - 1):
            raise base.InventoryBlocked("PROCESS_METADATA_INVALID")
        return item, None
    except PermissionError:
        return None, "access_denied"
    except (OSError, ValueError, base.InventoryBlocked):
        return None, "process_unavailable"


def collect(backend):
    try:
        before = backend.tcp_5432()
        pids = sorted({row[2] for row in before})
        first = {pid: safe_probe(backend.process_metadata, pid) for pid in pids}
        if backend.tcp_5432() != before:
            return {"status": "unavailable", "reason": "snapshot_changed", "items": None}
        final = {}
        for pid in pids:
            value, failure = first[pid]
            if failure:
                final[pid] = ("unknown", failure)
                continue
            again, second_failure = safe_probe(backend.process_metadata, pid)
            final[pid] = ((value[0], "stable_metadata") if not second_failure and again == value
                          else ("unknown", "process_changed"))
        aliases = {pid: "owner-" + str(i + 1) for i, pid in enumerate(pids)}
        items = [{"listener_alias": "listener-" + str(i + 1), "owner_alias": aliases[pid],
                  "port": PORT, "family": family, "bind": binding,
                  "owner_hint": final[pid][0], "attribution": final[pid][1]}
                 for i, (family, binding, pid) in enumerate(before)]
        return {"status": "measured" if all(v[1] == "stable_metadata" for v in final.values())
                else "partial", "items": items}
    except PermissionError:
        return {"status": "unavailable", "reason": "access_denied", "items": None}
    except (OSError, ValueError, base.InventoryBlocked):
        return {"status": "unavailable", "reason": "read_failed", "items": None}


def report(env, host, platform, backend_factory=WindowsOwnerMetadata):
    identity = base.provenance(env, host, platform)  # before any Windows metadata API
    backend = backend_factory()
    section = collect(backend)
    receipts = receipt_projection(backend.read_legacy_receipt)
    value = {"contract": "native-pg-readback-v1", **identity,
             "status": "measured" if section["status"] == "measured" and
                       all(r["status"] == "parsed" for r in receipts) else "partial",
             "scope": dict(SCOPE), "listener_owners_5432": section,
             "legacy_receipts": receipts,
             **{name: False for name in FALSE_FIELDS}}
    validate_report(value)
    return value


def validate_report(value):
    identity = {"host_alias", "source_sha", "rules_sha", "run_id", "run_attempt",
                "runner_version", "correlation_id"}
    if (not isinstance(value, dict)
            or set(value) != identity | set(FALSE_FIELDS) |
               {"contract", "status", "scope", "listener_owners_5432", "legacy_receipts"}
            or value["contract"] != "native-pg-readback-v1"
            or value["scope"] != SCOPE
            or any(value[name] is not False for name in FALSE_FIELDS)):
        raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
    if (value["host_alias"] != "authorized-primary"
            or not isinstance(value["source_sha"], str) or not base.SHA.fullmatch(value["source_sha"])
            or not isinstance(value["rules_sha"], str) or not base.SHA.fullmatch(value["rules_sha"])
            or not isinstance(value["run_id"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value["run_id"])
            or type(value["run_attempt"]) is not int or value["run_attempt"] != 1
            or not isinstance(value["runner_version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["runner_version"])
            or value["correlation_id"] != "dedicated-runner-" + value["run_id"] + "-1"):
        raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
    section = value["listener_owners_5432"]
    if section.get("status") == "unavailable":
        if (set(section) != {"status", "reason", "items"} or section["items"] is not None
                or section["reason"] not in ("snapshot_changed", "access_denied", "read_failed")):
            raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
    else:
        if (set(section) != {"status", "items"} or section["status"] not in ("measured", "partial")
                or not isinstance(section["items"], list) or len(section["items"]) > MAX_ITEMS):
            raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
        for item in section["items"]:
            if (set(item) != {"listener_alias", "owner_alias", "port", "family", "bind",
                              "owner_hint", "attribution"}
                    or not isinstance(item["listener_alias"], str)
                    or not re.fullmatch(r"listener-[1-9][0-9]?", item["listener_alias"])
                    or not isinstance(item["owner_alias"], str)
                    or not re.fullmatch(r"owner-[1-9][0-9]?", item["owner_alias"])
                    or type(item["port"]) is not int or item["port"] != PORT
                    or item["family"] not in ("ipv4", "ipv6")
                    or item["bind"] not in ("loopback", "wildcard", "other")
                    or item["owner_hint"] not in HINTS or item["attribution"] not in ATTRIBUTIONS
                    or (item["attribution"] == "stable_metadata") != (item["owner_hint"] != "unknown")):
                raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
        measured = all(item["attribution"] == "stable_metadata" for item in section["items"])
        if (section["status"] == "measured") != measured:
            raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
    receipts = value["legacy_receipts"]
    if not isinstance(receipts, list) or len(receipts) != 2:
        raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
    for receipt, (alias, _, contract) in zip(receipts, RECEIPTS):
        if not isinstance(receipt, dict) or receipt.get("alias") != alias:
            raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
        if receipt.get("status") != "parsed":
            if set(receipt) != {"alias", "status"} or receipt["status"] not in (
                    "missing", "access_denied", "unavailable_or_invalid"):
                raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
            continue
        common = {"alias", "status", "contract", "generated_date_utc", "historical_ready"}
        extra = ({"sql_event_readback", "sql_continuation_readback", "negative_control_passed"}
                 if alias == "legacy-e2e" else
                 {"restart_persistent", "restore_verified", "recorded_backup_bytes", "backup_hash_recorded"})
        if (set(receipt) != common | extra or receipt["contract"] != contract
                or not isinstance(receipt["generated_date_utc"], str)
                or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", receipt["generated_date_utc"])):
            raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
        for key in (extra | {"historical_ready"}) - {"recorded_backup_bytes"}:
            nullable_boolean(receipt[key])
        if "recorded_backup_bytes" in receipt:
            size = receipt["recorded_backup_bytes"]
            if size is not None and (type(size) is not int or not 0 <= size <= 2**63 - 1):
                raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
    complete = section["status"] == "measured" and all(r["status"] == "parsed" for r in receipts)
    if value["status"] != ("measured" if complete else "partial"):
        raise base.InventoryBlocked("REPORT_SCHEMA_REJECTED")
    if len(json.dumps(value)) > 32768:
        raise base.InventoryBlocked("REPORT_TOO_LARGE")


def main():
    try:
        if len(sys.argv) != 1:
            raise base.InventoryBlocked("ARGUMENTS_REJECTED")
        env = {name: os.environ.get(name, "") for name in base.CI_KEYS}
        evidence = report(env, socket.gethostname(), sys.platform)
    except (base.InventoryBlocked, OSError, ValueError, KeyError, TypeError, OverflowError):
        print('{"contract":"native-pg-readback-v1","status":"blocked"}')
        return 3
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["status"] == "measured" else 2


if __name__ == "__main__":
    raise SystemExit(main())

