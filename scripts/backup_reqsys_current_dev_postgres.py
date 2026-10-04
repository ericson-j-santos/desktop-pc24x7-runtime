#!/usr/bin/env python3
"""Protect the existing ReqSys DEV PostgreSQL snapshot locally; no plaintext file."""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time

import reqsys_dev_current_data_probe as probe

HEADER = b"REQSYS-PG-DPAPI-V1\0"
PROJECT = "wt-pc24x7-piloto"
MAX_BYTES = 32 * 1024 * 1024
TIMEOUT = 120


class BackupFailure(RuntimeError):
    pass


class Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def protect(data):
    if os.name != "nt":
        raise BackupFailure("windows_dpapi_required")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt.CryptProtectData.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob),
                                      ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptProtectData.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), buffer)
    destination = Blob()
    # CurrentUser, NULL optional entropy, UI_FORBIDDEN=1. Never LOCAL_MACHINE=4.
    if not crypt.CryptProtectData(ctypes.byref(source), "ReqSys DEV PostgreSQL snapshot",
                                 None, None, None, 1, ctypes.byref(destination)):
        raise BackupFailure("dpapi_protect_failed")
    try:
        return HEADER + ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel.LocalFree(ctypes.cast(destination.pbData, ctypes.c_void_p))

def unprotect(encrypted):
    if os.name != "nt" or not encrypted.startswith(HEADER) or len(encrypted) > MAX_BYTES + 1048576:
        raise BackupFailure("protected_archive_header_or_platform_invalid")
    payload = encrypted[len(HEADER):]
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.POINTER(wintypes.LPWSTR),
                                        ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    source = Blob(len(payload), buffer)
    destination = Blob()
    description = wintypes.LPWSTR()
    if not crypt.CryptUnprotectData(ctypes.byref(source), ctypes.byref(description),
                                    None, None, None, 1, ctypes.byref(destination)):
        raise BackupFailure("dpapi_unprotect_failed")
    try:
        if destination.cbData > MAX_BYTES:
            raise BackupFailure("decrypted_archive_size_limit")
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel.LocalFree(ctypes.cast(destination.pbData, ctypes.c_void_p))
        if description:
            kernel.LocalFree(ctypes.cast(description, ctypes.c_void_p))


def owner_sid():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise BackupFailure("owner_token_unavailable")
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if needed.value < ctypes.sizeof(ctypes.c_void_p) or needed.value > 65536:
            raise BackupFailure("owner_sid_invalid")
        data = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, data, needed, ctypes.byref(needed)):
            raise BackupFailure("owner_sid_unavailable")
        sid_pointer = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0]
        value = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(value)):
            raise BackupFailure("owner_sid_conversion_failed")
        try:
            sid = value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))
        if not re.fullmatch(r"S-1-[0-9-]+", sid or ""):
            raise BackupFailure("owner_sid_invalid")
        return sid
    finally:
        kernel.CloseHandle(token)


def private_acl(path, sid):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:P(A;OICI;FA;;;" + sid + ")", 1, ctypes.byref(descriptor), None):
        raise BackupFailure("private_acl_descriptor_failed")
    try:
        if not advapi.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor):
            raise BackupFailure("private_acl_failed")
    finally:
        kernel.LocalFree(descriptor)

def assert_private_acl(path, sid):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetFileSecurityW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    needed = wintypes.DWORD()
    advapi.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(needed))
    if needed.value < 20 or needed.value > 65536:
        raise BackupFailure("acl_readback_size_invalid")
    descriptor = ctypes.create_string_buffer(needed.value)
    if not advapi.GetFileSecurityW(str(path), 4, descriptor, needed, ctypes.byref(needed)):
        raise BackupFailure("acl_readback_failed")
    present, defaulted, acl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
    if not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)):
        raise BackupFailure("acl_descriptor_readback_failed")
    if not present.value or not acl.value:
        raise BackupFailure("null_acl_blocked")
    control, revision = wintypes.WORD(), wintypes.DWORD()
    if not advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)) or not control.value & 0x1000:
        raise BackupFailure("acl_inheritance_not_protected")
    ace_count = int.from_bytes(ctypes.string_at(acl.value + 4, 2), "little")
    if ace_count != 1:
        raise BackupFailure("acl_not_owner_only")
    ace = ctypes.c_void_p()
    if not advapi.GetAce(acl, 0, ctypes.byref(ace)):
        raise BackupFailure("acl_ace_readback_failed")
    header = ctypes.string_at(ace, 8)
    if header[0] != 0 or int.from_bytes(header[4:8], "little") != 0x1F01FF:
        raise BackupFailure("acl_owner_access_mismatch")
    value = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(ace.value + 8), ctypes.byref(value)):
        raise BackupFailure("acl_sid_readback_failed")
    try:
        if value.value != sid:
            raise BackupFailure("acl_owner_sid_mismatch")
    finally:
        kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))


def no_reparse(path):
    if not path.is_absolute():
        raise BackupFailure("private_path_not_absolute")
    for parent in (path, *path.parents):
        if parent.exists() and (parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction())):
            raise BackupFailure("private_path_reparse_blocked")


def private_root():
    raw = os.environ.get("LOCALAPPDATA")
    if not raw:
        raise BackupFailure("localappdata_missing")
    no_reparse(Path(raw))
    base = Path(raw).resolve()
    if not base.is_dir():
        raise BackupFailure("localappdata_unavailable")
    root = base / "ReqSys" / "SelfHostedDevMigration"
    for path in (base / "ReqSys", root):
        if path.exists() and (path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())):
            raise BackupFailure("private_path_reparse_blocked")
    root.mkdir(parents=True, exist_ok=True)
    sid = owner_sid()
    private_acl(root, sid)
    assert_private_acl(root, sid)
    return root, sid


def capture(command, *, input_bytes=None):
    """RAM-only bounded stdout. Drain/discard stderr; never print dump/errors."""
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data = bytearray()
    error = []
    def read_output():
        try:
            while True:
                block = process.stdout.read(65536)
                if not block:
                    return
                if len(data) + len(block) > MAX_BYTES:
                    error.append("archive_size_limit")
                    process.kill()
                    return
                data.extend(block)
        except OSError:
            error.append("archive_read_failed")
    def discard_errors():
        while process.stderr.read(65536):
            pass
    def write_input():
        try:
            if input_bytes is not None:
                process.stdin.write(input_bytes)
                process.stdin.close()
        except (OSError, BrokenPipeError):
            error.append("archive_input_failed")
    threads = [threading.Thread(target=read_output, daemon=True),
               threading.Thread(target=discard_errors, daemon=True)]
    if input_bytes is not None:
        threads.append(threading.Thread(target=write_input, daemon=True))
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        raise BackupFailure("archive_command_timeout") from None
    finally:
        for thread in threads:
            thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        raise BackupFailure("archive_pipe_not_closed")
    if error:
        raise BackupFailure(error[0])
    if process.returncode:
        raise BackupFailure("archive_command_failed")
    return bytes(data)


def validated_source(expected_build):
    result = probe.collect()
    if result.get("project") != PROJECT or result.get("host") != probe.HOST:
        raise BackupFailure("source_project_or_host_mismatch")
    if not result.get("gateway_api_route", {}).get("verified"):
        raise BackupFailure("source_gateway_route_unverified")
    if result.get("build_info", {}).get("build_sha") != expected_build:
        raise BackupFailure("source_build_mismatch")
    identity = result.get("configured_database", {})
    if (identity.get("dialect"), identity.get("database"), identity.get("role")) != ("postgresql", "reqsys", "reqsys_app"):
        raise BackupFailure("source_database_mismatch")
    metadata = result.get("data_metadata", {})
    if not metadata.get("counts_exact") or not isinstance(metadata.get("table_counts"), dict):
        raise BackupFailure("source_counts_unavailable")
    identifier = result.get("database_container", {}).get("container_id")
    if not probe.CONTAINER_ID.fullmatch(identifier or ""):
        raise BackupFailure("source_container_unverified")
    return result


def validate_toc(data):
    if len(data) > MAX_BYTES:
        raise BackupFailure("toc_too_large")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise BackupFailure("toc_encoding_invalid") from None
    tables = []
    for line in lines:
        if not line.strip() or line.startswith(";"):
            continue
        match = re.fullmatch(r"(\d+); (\d+) (\d+) (.+)", line)
        if not match:
            raise BackupFailure("toc_entry_invalid")
        descriptor = match.group(4)
        if re.search(r"\b(?:DATABASE|DATABASE PROPERTIES|EXTENSION|FOREIGN|SERVER|EVENT TRIGGER|SUBSCRIPTION|PUBLICATION|PROCEDURAL LANGUAGE)\b", descriptor):
            raise BackupFailure("toc_privileged_object_blocked")
        # All schema objects must belong to public and the existing application
        # owner. No custom code, executable function or arbitrary namespace.
        allowed = ("TABLE DATA", "SEQUENCE OWNED BY", "SEQUENCE SET", "DEFAULT",
                   "FK CONSTRAINT", "CONSTRAINT", "INDEX", "TABLE", "SEQUENCE",
                   "TYPE", "COMMENT", "ACL", "SCHEMA")
        kind = next((value for value in allowed if descriptor.startswith(value + " ")), None)
        if kind is None:
            raise BackupFailure("toc_object_kind_unapproved")
        remainder = descriptor[len(kind) + 1:]
        if kind == "SCHEMA":
            if remainder not in {"- public reqsys_app", "- public pg_database_owner"}:
                raise BackupFailure("toc_schema_unapproved")
        elif kind in {"COMMENT", "ACL"} and remainder.startswith("- SCHEMA public "):
            if not remainder.endswith(" reqsys_app") and not remainder.endswith(" pg_database_owner"):
                raise BackupFailure("toc_schema_owner_unapproved")
        elif not remainder.startswith("public ") or not remainder.endswith(" reqsys_app"):
            raise BackupFailure("toc_schema_or_owner_unapproved")
        if kind == "TABLE DATA":
            tables.append(remainder[len("public "): -len(" reqsys_app")])
    if not tables or len(set(tables)) != len(tables):
        raise BackupFailure("toc_table_data_missing_or_duplicate")
    return sorted(tables)


def observation(source):
    value = source["data_metadata"]
    return {key: value.get(key) for key in ("observed_at", "table_counts", "wal_lsn", "system_identifier", "transaction_snapshot")}


def backup(expected_build):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_build):
        raise BackupFailure("expected_build_sha_invalid")
    before = validated_source(expected_build)
    root, sid = private_root()
    archive_path = root / "current-dev-postgres.dump.dpapi"
    proof_path = root / "current-dev-postgres-proof.json"
    if archive_path.exists() or proof_path.exists():
        if not archive_path.is_file() or not proof_path.is_file():
            raise BackupFailure("existing_protected_backup_incomplete")
        no_reparse(archive_path)
        no_reparse(proof_path)
        assert_private_acl(archive_path, sid)
        assert_private_acl(proof_path, sid)
        if archive_path.stat().st_size > MAX_BYTES + 1048576 or proof_path.stat().st_size > 1048576:
            raise BackupFailure("existing_protected_backup_size_invalid")
        existing = json.loads(proof_path.read_text(encoding="utf-8"))
        encrypted = archive_path.read_bytes()
        plain = unprotect(encrypted)
        if (existing.get("contract") != "reqsys-current-dev-postgres-protected-backup"
            or existing.get("status") != "captured"
            or existing.get("source", {}).get("project") != PROJECT
            or existing.get("source", {}).get("build_sha") != expected_build
            or hashlib.sha256(encrypted).hexdigest() != existing.get("protection", {}).get("encrypted_sha256")
            or hashlib.sha256(plain).hexdigest() != existing.get("archive", {}).get("sha256")
            or not plain.startswith(b"PGDMP")):
            raise BackupFailure("existing_protected_backup_verification_failed")
        existing["reused_existing_snapshot"] = True
        existing["latest_source_observation"] = observation(before)
        existing["cutover_ready"] = False
        return existing
    docker = probe.shutil.which("docker")
    identifier = before["database_container"]["container_id"]
    archive = capture([docker, "exec", identifier, "pg_dump", "--format=custom", "--compress=0",
                       "--no-password", "--username=reqsys_app", "--dbname=reqsys",
                       "--lock-wait-timeout=5s"])
    if not archive.startswith(b"PGDMP"):
        raise BackupFailure("archive_format_invalid")
    table_names = validate_toc(capture([docker, "exec", "-i", identifier, "pg_restore", "--list"], input_bytes=archive))
    if table_names != sorted(before["data_metadata"]["table_counts"]):
        raise BackupFailure("archive_tables_differ_from_observation")
    after = validated_source(expected_build)
    if after["database_container"]["container_id"] != identifier or after["api"]["container_id"] != before["api"]["container_id"]:
        raise BackupFailure("source_runtime_changed")
    if before["data_metadata"].get("system_identifier") != after["data_metadata"].get("system_identifier"):
        raise BackupFailure("source_cluster_changed")
    encrypted = protect(archive)
    if archive_path.exists() or proof_path.exists():
        raise BackupFailure("existing_protected_backup_preserved")
    temporary = root / "current-dev-postgres.dump.dpapi.pending"
    if temporary.exists():
        raise BackupFailure("existing_pending_backup_preserved")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        private_acl(temporary, sid)
        temporary.replace(archive_path)
        assert_private_acl(archive_path, sid)
        if unprotect(encrypted) != archive:
            raise BackupFailure("dpapi_roundtrip_mismatch")
        proof = {
            "schema_version": "1.0.0", "contract": "reqsys-current-dev-postgres-protected-backup",
            "status": "captured", "captured_at": datetime.now(timezone.utc).isoformat(),
            "source": {"host": probe.HOST, "project": PROJECT, "api_container_id": before["api"]["container_id"],
                       "db_container_id": identifier, "build_sha": expected_build,
                       "database": "reqsys", "role": "reqsys_app",
                       "system_identifier": before["data_metadata"].get("system_identifier")},
            "archive": {"format": "postgresql_custom", "sha256": hashlib.sha256(archive).hexdigest(),
                        "size_bytes": len(archive), "toc_table_data_count": len(table_names)},
            "protection": {"kind": "windows-dpapi-current-user", "entropy": "none",
                           "header": "REQSYS-PG-DPAPI-V1", "encrypted_sha256": hashlib.sha256(encrypted).hexdigest(),
                           "encrypted_size_bytes": len(encrypted), "owner_only_acl": True},
            "source_observations": {"before": observation(before), "after": observation(after)},
            "observations_bound_to_archive_snapshot": False,
            "pg_dump_consistent_snapshot": True, "archive_toc_checked": True,
            "restore_verified": False, "contents_compared": False, "source_writes_frozen": False,
            "credentials_exported": False, "new_auth_keys_created": False,
            "plaintext_files_written": False, "services_changed": False, "production_touched": False,
            "keys_migrated": False, "offsite_backup": False, "portable_backup": False, "cutover_ready": False,
        }
        with proof_path.open("x", encoding="utf-8") as stream:
            json.dump(proof, stream, sort_keys=True, indent=2)
            stream.write("\n")
        private_acl(proof_path, sid)
        assert_private_acl(proof_path, sid)
        return proof
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-build-sha", required=True)
    args = parser.parse_args()
    try:
        result = backup(args.expected_build_sha)
    except (BackupFailure, probe.ProbeFailure) as error:
        result = {"status": "blocked", "error_code": str(error), "cutover_ready": False,
                  "plaintext_files_written": False, "credentials_exported": False}
    except Exception:
        result = {"status": "blocked", "error_code": "protected_backup_failed",
                  "cutover_ready": False, "plaintext_files_written": False, "credentials_exported": False}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "captured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
