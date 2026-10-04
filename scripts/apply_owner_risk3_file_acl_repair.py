#!/usr/bin/env python3
"""Closed, reviewed repair of the DACL on one fixed owner exception file."""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location(
    "_owner_acl_repair_plan", Path(__file__).with_name("plan_owner_risk3_file_acl_repair.py")
)
plan = importlib.util.module_from_spec(SPEC)
_old_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    SPEC.loader.exec_module(plan)
finally:
    sys.dont_write_bytecode = _old_bytecode
r = plan.registry
CONFIRM = "REPAIR-OWNER-RISK3-SINGLE-FILE-ACL"
BACKUP_ROOT = r.CONFIG_ROOT / "PrivateAclRepair"
BACKUP_FILE = BACKUP_ROOT / "owner-risk3-exceptions.original.dacl.dpapi"
PREFIX = b"REQSYS-OWNER-ACL-REPAIR-V1\x00"

class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

def dpapi(data, decrypt=False):
    if os.name != "nt" or not data or len(data) > 131072:
        raise r.OperationError("private_acl_backup_dpapi_input_invalid")
    api = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    protect = api.CryptProtectData
    protect.argtypes = [
        ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob),
    ]
    unprotect = api.CryptUnprotectData
    unprotect.argtypes = [
        ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob),
    ]
    raw = ctypes.create_string_buffer(data)
    incoming = Blob(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = Blob()
    success = unprotect(
        ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing)
    ) if decrypt else protect(
        ctypes.byref(incoming), "ReqSys owner ACL repair original descriptor",
        None, None, None, 1, ctypes.byref(outgoing),
    )
    if not success:
        raise r.OperationError("private_acl_backup_dpapi_failed")
    try:
        if outgoing.size > 131072:
            raise r.OperationError("private_acl_backup_dpapi_output_invalid")
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        kernel.LocalFree(ctypes.cast(outgoing.data, ctypes.c_void_p))

def security_text(path, private):
    """Read a backup directory/file security descriptor, never target JSON."""
    r.no_reparse(path)
    size = wintypes.DWORD()
    private.adv.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(size))
    if not size.value or size.value > 65536:
        raise r.OperationError("private_acl_backup_security_unavailable")
    descriptor = ctypes.create_string_buffer(size.value)
    if not private.adv.GetFileSecurityW(str(path), 5, descriptor, size.value, ctypes.byref(size)):
        raise r.OperationError("private_acl_backup_security_unavailable")
    text = ctypes.c_void_p()
    if not private.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor, 1, 5, ctypes.byref(text), None
    ):
        raise r.OperationError("private_acl_backup_security_unavailable")
    try:
        return ctypes.wstring_at(text)
    finally:
        private.kernel.LocalFree(text)

def set_security(path, private, sddl, information):
    r.no_reparse(path)
    descriptor = ctypes.c_void_p()
    if not private.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise r.OperationError("private_acl_descriptor_invalid")
    try:
        if not private.adv.SetFileSecurityW(str(path), information, descriptor):
            raise r.OperationError("private_acl_security_write_denied")
    finally:
        private.kernel.LocalFree(descriptor)

class PrivateBackup:
    """Fixed backup; DPAPI current-user scope and owner-only protected DACL."""
    def __init__(self, private):
        self.private = private

    def check(self, path):
        flags = "OICI" if path.is_dir() else ""
        value = security_text(path, self.private)
        match = re.fullmatch(
            r"O:([^:]+)D:P(?:AI)?\(A;" + flags + r";FA;;;([^)]+)\)", value
        )
        if not match or any(
            self.private._canonical_sid(identity) != self.private._canonical_sid(self.private.sid)
            for identity in match.groups()
        ):
            raise r.OperationError("private_acl_backup_not_owner_only")

    def secure_empty(self, path):
        flags = "OICI" if path.is_dir() else ""
        set_security(
            path, self.private,
            f"O:{self.private.sid}D:P(A;{flags};FA;;;{self.private.sid})",
            0x80000005,
        )
        self.check(path)

    def preserve(self, original):
        r.no_reparse(r.CONFIG_ROOT)
        if not BACKUP_ROOT.exists():
            BACKUP_ROOT.mkdir()
            self.secure_empty(BACKUP_ROOT)
        else:
            self.check(BACKUP_ROOT)
        plaintext = PREFIX + original.encode("utf-8")
        if BACKUP_FILE.exists():
            self.check(BACKUP_FILE)
            if BACKUP_FILE.stat().st_size > 131072:
                raise r.OperationError("private_acl_backup_too_large")
            if dpapi(BACKUP_FILE.read_bytes(), decrypt=True) != plaintext:
                raise r.OperationError("private_acl_backup_binding_mismatch")
            return
        encrypted = dpapi(plaintext)
        fd = -1
        try:
            fd = os.open(BACKUP_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.secure_empty(BACKUP_FILE)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            self.check(BACKUP_FILE)
            if dpapi(BACKUP_FILE.read_bytes(), decrypt=True) != plaintext:
                raise r.OperationError("private_acl_backup_roundtrip_failed")
        finally:
            if fd != -1:
                os.close(fd)

def verify_target(original, after, private):
    match = re.fullmatch(r"O:([^:]+)D:P(?:AI)?((?:\(A;;FA;;;[^)]+\)){2})", after)
    previous = re.match(r"O:([^:]+)D:", original)
    if not match or not previous:
        raise r.OperationError("repaired_acl_verification_failed")
    if private._canonical_sid(match.group(1)) != private._canonical_sid(previous.group(1)):
        raise r.OperationError("repaired_acl_owner_changed")
    identities = re.findall(r"\(A;;FA;;;([^)]+)\)", match.group(2))
    expected = [private._canonical_sid(private.sid), private._canonical_sid("SY")]
    if sorted(private._canonical_sid(value) for value in identities) != sorted(expected):
        raise r.OperationError("repaired_acl_verification_failed")

def apply_reviewed(path, private, original, confirm, reviewed_plan_sha256, backup):
    evidence = plan.build_plan(original, private)
    if confirm != CONFIRM:
        raise r.OperationError("closed_acl_repair_confirmation_required")
    if not r.DIGEST.fullmatch(reviewed_plan_sha256 or ""):
        raise r.OperationError("reviewed_acl_plan_sha256_required")
    if reviewed_plan_sha256 != evidence["plan_sha256"]:
        raise r.OperationError("reviewed_acl_plan_changed")
    if plan.read_security(path, private) != original:
        raise r.OperationError("configuration_acl_changed_before_backup")
    # An already-private DACL is an idempotent replay, without a new backup.
    try:
        verify_target(original, original, private)
    except r.OperationError:
        pass
    else:
        return {"status": "unchanged", "read_only": True, "configuration_bytes_changed": False}
    backup.preserve(original)
    if plan.read_security(path, private) != original:
        raise r.OperationError("configuration_acl_changed_before_repair")
    # DACL only: file owner, JSON bytes, grants, parent directory and audits stay intact.
    set_security(path, private, f"D:P(A;;FA;;;{private.sid})(A;;FA;;;SY)", 0x80000004)
    after = plan.read_security(path, private)
    verify_target(original, after, private)
    return {
        "status": "repaired", "read_only": False,
        "owner_preserved": True, "configuration_bytes_changed": False,
        "grants_changed": False, "parent_or_audit_acl_changed": False,
        "private_dpapi_backup_verified": True, "plan_sha256": reviewed_plan_sha256,
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--reviewed-plan-sha256", default="")
    args = parser.parse_args(argv)
    if not args.apply:
        if args.confirm or args.reviewed_plan_sha256:
            parser.error("apply-only arguments require --apply")
        return plan.main([])
    try:
        r.require_owner()
        private = r.WindowsPrivateFiles()
        path = r.CONFIG_ROOT / r.CONFIG_NAME
        original = plan.read_security(path, private)
        evidence = apply_reviewed(
            path, private, original, args.confirm, args.reviewed_plan_sha256,
            PrivateBackup(private),
        )
    except Exception as exc:
        code = exc.code if isinstance(exc, r.OperationError) else "acl_repair_failed"
        print(json.dumps({"status": "blocked", "code": code}, sort_keys=True))
        return 2
    print(json.dumps(evidence, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
