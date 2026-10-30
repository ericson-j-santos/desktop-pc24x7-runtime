"""Audit-only durable at-most-once request claim; invoke through Gateway risk 2.

Never deletes, repairs or retries a claim. This is not configuration mutation.
A successful claim followed by interruption is consumed/uncertain, not retryable.
"""
from __future__ import annotations
import ctypes
import json
import os
import re
import socket
import stat
from contextlib import contextmanager
from pathlib import Path

HOST = "DESKTOP-PDQK954"
REQUEST = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")

class ClaimError(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise ClaimError(reason)

def validate_metadata(data):
    require(type(data) is dict and set(data) == {"request_id", "source_sha", "rules_sha", "issue_id", "issue_number", "run_id", "run_attempt", "host"}, "CLAIM_FIELDS_INVALID")
    require(all(type(value) is str for value in data.values()), "CLAIM_TYPES_INVALID")
    require(bool(REQUEST.fullmatch(data["request_id"])) and bool(SHA.fullmatch(data["source_sha"])) and bool(SHA.fullmatch(data["rules_sha"])), "CLAIM_IDENTITY_INVALID")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", data[key]) for key in ("issue_id", "issue_number", "run_id")), "CLAIM_IDENTIFIERS_INVALID")
    require(data["run_attempt"] == "1" and data["host"] == HOST, "CLAIM_SCOPE_INVALID")

def ordinary(path, directory):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "REPARSE_REJECTED")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "FILE_TYPE_REJECTED")
    if not directory:
        require(info.st_nlink == 1, "HARDLINK_REJECTED")
    return info

@contextmanager
def windows_private_root(root):
    """Pin ancestors without FILE_SHARE_DELETE; verify root DACL and owner.

    Same-identity untrusted processes are outside this boundary and prohibited.
    Fail closed; never modify permissions or create a replacement audit root.
    """
    require(os.name == "nt" and root.is_absolute() and not str(root).startswith("\\\\"), "LOCAL_WINDOWS_ROOT_REQUIRED")
    from ctypes import wintypes as w
    kernel, advapi = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.GetDriveTypeW.argtypes = [w.LPCWSTR]
    kernel.GetDriveTypeW.restype = w.UINT
    kernel.GetVolumeInformationW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD]
    kernel.GetVolumeInformationW.restype = w.BOOL
    require(kernel.GetDriveTypeW(root.anchor) == 3, "FIXED_LOCAL_VOLUME_REQUIRED")
    filesystem = ctypes.create_unicode_buffer(32)
    require(bool(kernel.GetVolumeInformationW(root.anchor, None, 0, None, None, None, filesystem, 32)) and filesystem.value == "NTFS", "SUPPORTED_PERSISTENT_FILESYSTEM_REQUIRED")
    advapi.GetSecurityInfo.argtypes = [w.HANDLE, ctypes.c_int, w.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityInfo.restype = w.DWORD
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
    advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi.IsWellKnownSid.argtypes = [ctypes.c_void_p, ctypes.c_int]
    advapi.GetAce.argtypes = [ctypes.c_void_p, w.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    class FileInfo(ctypes.Structure):
        _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME), ("written", w.FILETIME), ("volume", w.DWORD), ("size_high", w.DWORD), ("size_low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]
    kernel.GetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.POINTER(FileInfo)]
    kernel.GetFileInformationByHandle.restype = w.BOOL
    advapi.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = w.BOOL
    installer = ctypes.c_void_p()
    token = w.HANDLE()
    handles = []
    descriptor = ctypes.c_void_p()
    try:
        require(bool(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token))), "TOKEN_IDENTITY_UNAVAILABLE")
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        require(0 < size.value <= 65536, "TOKEN_IDENTITY_INVALID")
        buffer = ctypes.create_string_buffer(size.value)
        require(bool(advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size))), "TOKEN_IDENTITY_UNAVAILABLE")
        current_sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        require(bool(advapi.ConvertStringSidToSidW("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", ctypes.byref(installer))), "OS_TRUST_SID_UNAVAILABLE")
        def trusted(sid):
            return bool(advapi.EqualSid(sid, current_sid) or advapi.IsWellKnownSid(sid, 22) or advapi.IsWellKnownSid(sid, 26) or advapi.EqualSid(sid, installer))
        for path in list(reversed(root.parents)) + [root]:
            ordinary(path, True)
            handle = kernel.CreateFileW(str(path), 0x20080, 3, None, 3, 0x02200000, None)
            require(handle != ctypes.c_void_p(-1).value and handle is not None, "AUDIT_DIRECTORY_HANDLE_UNAVAILABLE")
            handles.append(handle)
            observed = ordinary(path, True)
            opened = FileInfo()
            require(bool(kernel.GetFileInformationByHandle(handle, ctypes.byref(opened))), "DIRECTORY_HANDLE_INFO_UNAVAILABLE")
            require(bool(opened.attributes & 0x10) and not opened.attributes & 0x400 and observed.st_ino == ((opened.index_high << 32) | opened.index_low), "DIRECTORY_HANDLE_IDENTITY_REJECTED")
        def verify_security(security_handle, strict=True):
            nonlocal descriptor
            owner, dacl = ctypes.c_void_p(), ctypes.c_void_p()
            require(advapi.GetSecurityInfo(security_handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0, "AUDIT_SECURITY_UNAVAILABLE")
            require(bool(owner.value) and (bool(advapi.EqualSid(owner, current_sid)) if strict else trusted(owner)), "AUDIT_OWNER_REJECTED")
            require(bool(dacl.value), "NULL_DACL_REJECTED")
            # ACL header: byte revision, byte reserved, ushort size/count/reserved.
            header = ctypes.string_at(dacl, 8)
            count = int.from_bytes(header[4:6], "little")
            require(0 < count <= 128, "DACL_INVALID")
            current_allowed = False
            for index in range(count):
                ace = ctypes.c_void_p()
                require(bool(advapi.GetAce(dacl, index, ctypes.byref(ace))), "DACL_ACE_UNAVAILABLE")
                ace_header = ctypes.string_at(ace, 4)
                ace_type, ace_size = ace_header[0], int.from_bytes(ace_header[2:4], "little")
                require(ace_type in (0, 1) and ace_size >= 12, "DACL_ACE_UNSUPPORTED")
                if ace_type == 0:
                    sid = ctypes.c_void_p(ace.value + 8)
                    ours = bool(advapi.EqualSid(sid, current_sid))
                    if strict:
                        require(trusted(sid), "DACL_OTHER_PRINCIPAL_REJECTED")
                    elif not ace_header[1] & 0x08 and not trusted(sid):
                        mask = int.from_bytes(ctypes.string_at(ace.value + 4, 4), "little")
                        require(not mask & 0x500D0142, "ANCESTOR_MUTATION_GRANT_REJECTED")
                    current_allowed = current_allowed or ours
            require(not strict or current_allowed, "DACL_CURRENT_IDENTITY_REQUIRED")
            kernel.LocalFree(descriptor)
            descriptor = ctypes.c_void_p()
        for ancestor_handle in handles[:-1]:
            verify_security(ancestor_handle, strict=False)
        verify_security(handles[-1])
        def verify_open_file(fd):
            import msvcrt
            verify_security(msvcrt.get_osfhandle(fd))
        yield verify_open_file
        ordinary(root, True)
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)
        for handle in reversed(handles):
            kernel.CloseHandle(handle)
        if token.value:
            kernel.CloseHandle(token)
        if installer.value:
            kernel.LocalFree(installer)

def claim(root, metadata, guard=windows_private_root):
    validate_metadata(metadata)
    with guard(root) as verify_open_file:
        ordinary(root, True)
        target = root / ("desktop-capacity-" + metadata["request_id"] + ".claim.json")
        # O_EXCL is the linearization point. Existing/corrupt/partial claims block.
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError:
            raise ClaimError("REQUEST_ALREADY_CONSUMED_OR_UNCERTAIN") from None
        payload = json.dumps({**metadata, "schema": 1, "state": "CLAIMED_UNCERTAIN", "audit_state_changed": True, "configuration_changed": False}, sort_keys=True).encode("ascii")
        with os.fdopen(fd, "wb") as stream:
            require(callable(verify_open_file), "CLAIM_SECURITY_VERIFIER_REQUIRED")
            verify_open_file(stream.fileno())
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "CLAIM_FILE_REJECTED")
        first = ordinary(target, False)
        with target.open("rb") as stream:
            observed = stream.read(len(payload) + 1)
            opened = os.fstat(stream.fileno())
        after = ordinary(target, False)
        require((info.st_dev, info.st_ino) == (first.st_dev, first.st_ino) == (opened.st_dev, opened.st_ino) == (after.st_dev, after.st_ino) and observed == payload, "CLAIM_READBACK_FAILED")
        return {"claimed": True, "request_id": metadata["request_id"], "audit_state_changed": True, "configuration_changed": False}

def main():
    try:
        require(socket.gethostname().upper() == HOST and os.name == "nt", "HOST_REJECTED")
        # Re-read the original issue and source pins immediately before consuming it.
        import importlib.util
        spec = importlib.util.spec_from_file_location("capacity_admission", Path(__file__).with_name("desktop_gitlab_capacity_admission.py"))
        admission = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(admission)
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        request = admission.assess(event, os.environ, admission.api_get)
        require(request["request_id"] == os.environ.get("CAPACITY_REQUEST_ID") and request["expected_head_sha"] == os.environ.get("EXPECTED_HEAD") and request["expected_rules_sha"] == os.environ.get("EXPECTED_RULES") and request["issue_id"] == os.environ.get("CAPACITY_ISSUE_ID") and request["issue_number"] == os.environ.get("CAPACITY_ISSUE_NUMBER"), "ADMITTED_REQUEST_CHANGED")
        base = Path(os.environ["LOCALAPPDATA"])
        root = base / "ReqSys" / "CommandGateway"
        data = {"request_id": os.environ["CAPACITY_REQUEST_ID"], "source_sha": os.environ["EXPECTED_HEAD"], "rules_sha": os.environ["EXPECTED_RULES"], "issue_id": os.environ["CAPACITY_ISSUE_ID"], "issue_number": os.environ["CAPACITY_ISSUE_NUMBER"], "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "host": HOST}
        print(json.dumps(claim(root, data), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"claimed": False, "reason": str(exc) if isinstance(exc, ClaimError) else type(exc).__name__, "configuration_changed": False}))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
