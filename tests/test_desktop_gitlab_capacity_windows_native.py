"""Native Windows fixture gates; Linux skips are explicit, not Windows evidence.

No production host collection or ACL repair. DACL negative controls affect only
fresh disposable fixtures and are restored before cleanup. Windows CI must
execute these tests; API mocks are a separate test module.

The hosted parent intentionally retains its incompatible Administrators default
owner and proves rejection. Only a verified distinct-token child temporarily
uses its existing TokenUser as TokenOwner, restoring it before success. This is
fixture context, NOT a production token repair or proof of a physical Desktop.
"""
from __future__ import annotations
import concurrent.futures
import contextlib
import ctypes
import functools
import importlib.util
import json
import os
import shutil
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
import uuid
from unittest.mock import patch

_NATIVE_CHILD = False

class FixtureToken:
    """Own-process fixture token only; never enables privileges or changes groups."""
    def __init__(self, access=8):
        from ctypes import wintypes as w
        self.w, self.p = w, ctypes.c_void_p
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
        self.advapi.OpenProcessToken.restype = w.BOOL
        self.advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, self.p, w.DWORD, ctypes.POINTER(w.DWORD)]
        self.advapi.GetTokenInformation.restype = w.BOOL
        self.advapi.GetLengthSid.argtypes = [self.p]
        self.advapi.GetLengthSid.restype = w.DWORD
        self.advapi.SetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, self.p, w.DWORD]
        self.advapi.SetTokenInformation.restype = w.BOOL
        self.handle = w.HANDLE()
        if access not in (8, 8 | 0x80) or not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), access, ctypes.byref(self.handle)):
            raise AssertionError("FIXTURE_OWN_TOKEN_ACCESS_FAILED")

    def close(self):
        if self.handle.value:
            if not self.kernel.CloseHandle(self.handle):
                raise AssertionError("FIXTURE_TOKEN_CLOSE_FAILED")
            self.handle = self.w.HANDLE()

    def query(self, kind):
        size = self.w.DWORD()
        self.advapi.GetTokenInformation(self.handle, kind, None, 0, ctypes.byref(size))
        if not 0 < size.value <= 1048576:
            raise AssertionError("FIXTURE_TOKEN_SIZE_INVALID")
        buffer = ctypes.create_string_buffer(size.value)
        if not self.advapi.GetTokenInformation(self.handle, kind, buffer, size, ctypes.byref(size)):
            raise AssertionError("FIXTURE_TOKEN_QUERY_FAILED")
        return buffer

    def sid_bytes(self, pointer):
        size = self.advapi.GetLengthSid(pointer)
        if not 8 <= size <= 68:
            raise AssertionError("FIXTURE_SID_SIZE_INVALID")
        return ctypes.string_at(pointer, size)

    def snapshot(self):
        w, p = self.w, self.p
        class Luid(ctypes.Structure):
            _fields_ = [("low", w.DWORD), ("high", w.LONG)]
        class Statistics(ctypes.Structure):
            _fields_ = [("token", Luid), ("authentication", Luid), ("expiration", ctypes.c_longlong), ("kind", ctypes.c_int), ("level", ctypes.c_int), ("charged", w.DWORD), ("available", w.DWORD), ("groups", w.DWORD), ("privileges", w.DWORD), ("modified", Luid)]
        class SidAttributes(ctypes.Structure):
            _fields_ = [("sid", p), ("attributes", w.DWORD)]
        class Groups(ctypes.Structure):
            _fields_ = [("count", w.DWORD), ("first", SidAttributes)]
        class LuidAttributes(ctypes.Structure):
            _fields_ = [("luid", Luid), ("attributes", w.DWORD)]
        class Privileges(ctypes.Structure):
            _fields_ = [("count", w.DWORD), ("first", LuidAttributes)]
        buffers = {kind: self.query(kind) for kind in (1, 2, 3, 4, 6, 10)}
        def sid(kind):
            return self.sid_bytes(ctypes.cast(buffers[kind], ctypes.POINTER(p))[0]).hex()
        def entries(kind, header, entry):
            count = ctypes.cast(buffers[kind], ctypes.POINTER(w.DWORD))[0]
            if count > 4096 or header.first.offset + count * ctypes.sizeof(entry) > len(buffers[kind]):
                raise AssertionError("FIXTURE_TOKEN_ARRAY_INVALID")
            return (entry.from_buffer(buffers[kind], header.first.offset + i * ctypes.sizeof(entry)) for i in range(count))
        groups = sorted((self.sid_bytes(e.sid).hex(), e.attributes) for e in entries(2, Groups, SidAttributes))
        privileges = sorted((e.luid.low, e.luid.high, e.attributes) for e in entries(3, Privileges, LuidAttributes))
        acl = ctypes.cast(buffers[6], ctypes.POINTER(p))[0]
        default_dacl = None
        if acl:
            acl_size = int.from_bytes(ctypes.string_at(acl, 4)[2:4], "little")
            if not 8 <= acl_size <= 65535:
                raise AssertionError("FIXTURE_TOKEN_DACL_INVALID")
            default_dacl = ctypes.string_at(acl, acl_size).hex()
        if len(buffers[10]) < ctypes.sizeof(Statistics):
            raise AssertionError("FIXTURE_TOKEN_STATISTICS_INVALID")
        statistics = Statistics.from_buffer(buffers[10])
        return {"token_id": (statistics.token.low, statistics.token.high), "modified_id": (statistics.modified.low, statistics.modified.high), "user": sid(1), "owner": sid(4), "groups": groups, "privileges": privileges, "default_dacl": default_dacl}

    def set_own_owner(self, sid_bytes):
        # The caller supplies only its saved owner or its existing TokenUser SID.
        buffer = ctypes.create_string_buffer(sid_bytes)
        owner = self.p(ctypes.addressof(buffer))
        if not self.advapi.SetTokenInformation(self.handle, 4, ctypes.byref(owner), ctypes.sizeof(owner)):
            raise AssertionError("FIXTURE_TOKEN_OWNER_SET_FAILED")

def invariant_token(snapshot):
    return {key: value for key, value in snapshot.items() if key not in ("owner", "modified_id")}

@contextlib.contextmanager
def isolated_owner_context(parent_token_id):
    query = FixtureToken()
    try:
        original = query.snapshot()
        if list(original["token_id"]) == parent_token_id:
            raise AssertionError("FIXTURE_TOKEN_NOT_ISOLATED_NO_SETTER_EXECUTED")
    finally:
        query.close()
    token = FixtureToken(8 | 0x80)  # QUERY | ADJUST_DEFAULT, never ADJUST_PRIVILEGES.
    attempted = False
    try:
        if token.snapshot() != original:
            raise AssertionError("FIXTURE_TOKEN_CHANGED_BEFORE_SETTER")
        attempted = True
        token.set_own_owner(bytes.fromhex(original["user"]))
        changed = token.snapshot()
        if changed["owner"] != original["user"] or invariant_token(changed) != invariant_token(original):
            raise AssertionError("FIXTURE_TOKEN_CHANGE_OUT_OF_SCOPE")
        yield
    finally:
        try:
            if attempted:
                invariant_ok = False
                try:
                    invariant_ok = invariant_token(token.snapshot()) == invariant_token(original)
                finally:
                    # Even a failed invariant query must not bypass restoration.
                    token.set_own_owner(bytes.fromhex(original["owner"]))
                restored = token.snapshot()
                if not invariant_ok or restored["owner"] != original["owner"] or invariant_token(restored) != invariant_token(original):
                    raise AssertionError("FIXTURE_TOKEN_RESTORE_OR_INVARIANT_FAILED")
        finally:
            token.close()

def isolated_native_test(function):
    @functools.wraps(function)
    def wrapped(self):
        if _NATIVE_CHILD:
            return function(self)
        token = FixtureToken()
        try:
            before = token.snapshot()
            self.assertTrue(before["owner"] != before["user"], "Original hosted owner-mismatch control must be exercised")
            with tempfile.TemporaryDirectory(prefix="capacity-original-owner-") as directory:
                with self.assertRaisesRegex(m.ClaimError, "AUDIT_OWNER_REJECTED"):
                    m.claim(Path(directory), META)
                self.assertEqual(list(Path(directory).iterdir()), [])
            try:
                result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--capacity-native-child", function.__name__, json.dumps(before["token_id"])], capture_output=True, text=True, timeout=180, check=False)
            finally:
                self.assertTrue(token.snapshot() == before, "Parent process token must remain exactly unchanged")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipts = [json.loads(line.removeprefix("CAPACITY_NATIVE_RECEIPT ")) for line in result.stdout.splitlines() if line.startswith("CAPACITY_NATIVE_RECEIPT ")]
            self.assertEqual(receipts, [{"test": function.__name__, "tests_run": 1, "skipped": 0, "successful": True, "token_isolated": True, "owner_restored": True, "security_invariants": True}])
        finally:
            token.close()
    return wrapped

class FixtureIsolationProtocolTests(unittest.TestCase):
    """Portable protocol controls only; never evidence of the native Win32 ABI."""
    def token_factory(self, *, same=False):
        state = {"token_id": (1, 2) if same else (3, 4), "modified_id": (5, 6), "user": "01", "owner": "02", "groups": [("group", 1)], "privileges": [(7, 8, 9)], "default_dacl": "acl"}
        calls = []
        class FakeToken:
            def __init__(self, access=8):
                calls.append(("open", access))
            def snapshot(self):
                return dict(state)
            def set_own_owner(self, value):
                calls.append(("owner", value.hex()))
                state["owner"] = value.hex()
            def close(self):
                calls.append(("close",))
        return state, calls, FakeToken

    def test_equal_token_id_never_opens_adjust_or_sets_owner(self):
        state, calls, fake = self.token_factory(same=True)
        with patch.dict(globals(), {"FixtureToken": fake}), self.assertRaisesRegex(AssertionError, "NOT_ISOLATED"):
            with isolated_owner_context([1, 2]):
                self.fail("body must not execute")
        self.assertNotIn(("open", 0x88), calls)
        self.assertFalse(any(call[0] == "owner" for call in calls))
        self.assertEqual(state["owner"], "02")

    def test_distinct_token_runs_body_and_restores_original_owner(self):
        state, calls, fake = self.token_factory()
        with patch.dict(globals(), {"FixtureToken": fake}):
            with isolated_owner_context([1, 2]):
                self.assertEqual(state["owner"], "01")
        self.assertEqual(state["owner"], "02")
        self.assertEqual([call for call in calls if call[0] == "owner"], [("owner", "01"), ("owner", "02")])

    def test_test_failure_still_restores_owner(self):
        state, calls, fake = self.token_factory()
        with patch.dict(globals(), {"FixtureToken": fake}), self.assertRaisesRegex(RuntimeError, "test failed"):
            with isolated_owner_context([1, 2]):
                raise RuntimeError("test failed")
        self.assertEqual(state["owner"], "02")

    def test_privilege_drift_is_failure_not_success_receipt(self):
        state, calls, fake = self.token_factory()
        with patch.dict(globals(), {"FixtureToken": fake}), self.assertRaisesRegex(AssertionError, "INVARIANT_FAILED"):
            with isolated_owner_context([1, 2]):
                state["privileges"] = [(7, 8, 10)]
        self.assertEqual(state["owner"], "02")

spec = importlib.util.spec_from_file_location("capacity_native_claim", Path(__file__).resolve().parents[1] / "scripts/desktop_gitlab_capacity_claim.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
META = {"request_id": "fedcba98-7654-4321-8123-456789abcdef", "source_sha": "a" * 40, "rules_sha": "b" * 40, "issue_id": "100", "issue_number": "12", "run_id": "123456789", "run_attempt": "1", "host": m.HOST}

def fixture_owner_diagnostic(path):
    """Query owner classes on disposable fixtures; never mutate security/token."""
    from ctypes import wintypes as w
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    p = ctypes.c_void_p
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [p]
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, p, w.DWORD, ctypes.POINTER(w.DWORD)]
    advapi.GetTokenInformation.restype = w.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p)]
    advapi.GetNamedSecurityInfoW.restype = w.DWORD
    advapi.EqualSid.argtypes = [p, p]
    advapi.EqualSid.restype = w.BOOL
    advapi.IsWellKnownSid.argtypes = [p, ctypes.c_int]
    advapi.IsWellKnownSid.restype = w.BOOL
    token, descriptor, owner = w.HANDLE(), p(), p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            return "owner_diagnostic=token_unavailable"
        buffers = []
        for kind in (1, 4):  # TokenUser, TokenOwner; query only.
            size = w.DWORD()
            advapi.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
            if not 0 < size.value <= 65536:
                return "owner_diagnostic=token_size_invalid"
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, kind, buffer, size, ctypes.byref(size)):
                return "owner_diagnostic=token_query_failed"
            buffers.append(buffer)
        user, default_owner = [ctypes.cast(buffer, ctypes.POINTER(p))[0] for buffer in buffers]
        def classify(sid):
            if not sid:
                return "missing"
            if advapi.EqualSid(sid, user):
                return "token_user"
            if advapi.IsWellKnownSid(sid, 26):
                return "builtin_administrators"
            if advapi.IsWellKnownSid(sid, 22):
                return "local_system"
            return "other"
        def observe(target):
            nonlocal descriptor
            if advapi.GetNamedSecurityInfoW(str(target), 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor)) != 0:
                return "query_failed"
            try:
                return (classify(owner.value) + ",equals_token_user=" + str(bool(advapi.EqualSid(owner, user)))
                        + ",equals_token_owner=" + str(bool(advapi.EqualSid(owner, default_owner))))
            finally:
                kernel.LocalFree(descriptor)
                descriptor = p()
        directory = observe(path)
        probe = path / "owner-diagnostic.tmp"
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            os.close(fd)
            created = observe(probe)
        finally:
            probe.unlink()
        return ("directory_owner=" + directory + "; new_file_owner=" + created
                + "; token_default_owner=" + classify(default_owner)
                + "; token_owner_equals_user=" + str(bool(advapi.EqualSid(default_owner, user))))
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)
        if token.value:
            kernel.CloseHandle(token)

def verify_private_fixture_acl(path, *, directory):
    """Read back the exact newly-created fixture ACL; never repair a mismatch."""
    from ctypes import wintypes as w
    p = ctypes.c_void_p
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [p]
    advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p)]
    advapi.GetNamedSecurityInfoW.restype = w.DWORD
    advapi.GetSecurityDescriptorControl.argtypes = [p, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = w.BOOL
    advapi.GetAce.argtypes = [p, w.DWORD, ctypes.POINTER(p)]
    advapi.GetAce.restype = w.BOOL
    advapi.EqualSid.argtypes = [p, p]
    advapi.EqualSid.restype = w.BOOL
    advapi.IsWellKnownSid.argtypes = [p, ctypes.c_int]
    advapi.IsWellKnownSid.restype = w.BOOL
    token = FixtureToken()
    try:
        user = ctypes.create_string_buffer(bytes.fromhex(token.snapshot()["user"]))
    finally:
        token.close()
    descriptor, owner, dacl = p(), p(), p()
    before = m.ordinary(path, directory)
    try:
        if advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) != 0:
            raise AssertionError("FIXTURE_SECURITY_READBACK_FAILED")
        if not owner.value or not advapi.EqualSid(owner, user) or not dacl.value:
            raise AssertionError("FIXTURE_OWNER_OR_DACL_INVALID")
        control, revision = w.WORD(), w.DWORD()
        if not advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise AssertionError("FIXTURE_CONTROL_READBACK_FAILED")
        if directory and not control.value & 0x1000:
            raise AssertionError("FIXTURE_DACL_NOT_PROTECTED")
        if int.from_bytes(ctypes.string_at(dacl, 8)[4:6], "little") != 3:
            raise AssertionError("FIXTURE_ACE_COUNT_INVALID")
        principals = []
        for index in range(3):
            ace = p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise AssertionError("FIXTURE_ACE_READBACK_FAILED")
            header = ctypes.string_at(ace, 8)
            if header[0] != 0 or header[1] != (3 if directory else 16) or int.from_bytes(header[2:4], "little") < 12 or int.from_bytes(header[4:8], "little") != 0x1F01FF:
                raise AssertionError("FIXTURE_ACE_SHAPE_INVALID")
            sid = p(ace.value + 8)
            if advapi.EqualSid(sid, user):
                principals.append("current_user")
            elif advapi.IsWellKnownSid(sid, 22):
                principals.append("system")
            elif advapi.IsWellKnownSid(sid, 26):
                principals.append("administrators")
            else:
                raise AssertionError("FIXTURE_UNEXPECTED_PRINCIPAL")
        if sorted(principals) != ["administrators", "current_user", "system"]:
            raise AssertionError("FIXTURE_PRINCIPALS_INVALID")
        after = m.ordinary(path, directory)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise AssertionError("FIXTURE_IDENTITY_CHANGED")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)

@contextlib.contextmanager
def new_private_native_fixture():
    """Create a NEW root with explicit user/SYSTEM/Admin ACL; no existing ACL edit."""
    from ctypes import wintypes as w
    p = ctypes.c_void_p
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", p), ("inherit_handle", w.BOOL)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    kernel.CreateDirectoryW.restype = w.BOOL
    kernel.LocalFree.argtypes = [p]
    advapi.ConvertSidToStringSidW.argtypes = [p, ctypes.POINTER(w.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = w.BOOL
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(p), ctypes.POINTER(w.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    token = FixtureToken()
    try:
        user = ctypes.create_string_buffer(bytes.fromhex(token.snapshot()["user"]))
    finally:
        token.close()
    user_string, descriptor = w.LPWSTR(), p()
    root = Path(tempfile.gettempdir()) / ("capacity-native-" + uuid.uuid4().hex)
    created = False
    try:
        if not advapi.ConvertSidToStringSidW(user, ctypes.byref(user_string)):
            raise AssertionError("FIXTURE_USER_SID_ENCODING_FAILED")
        sddl = "D:P(A;OICI;FA;;;" + user_string.value + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise AssertionError("FIXTURE_PRIVATE_DESCRIPTOR_FAILED")
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        # A collision or denied creation fails closed; never reuse/repair a path.
        if not kernel.CreateDirectoryW(str(root), ctypes.byref(attributes)):
            raise AssertionError("FIXTURE_EXCLUSIVE_CREATION_FAILED")
        created = True
        verify_private_fixture_acl(root, directory=True)
        probe = root / "inheritance-probe.tmp"
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            os.close(fd)
            verify_private_fixture_acl(probe, directory=False)
        finally:
            probe.unlink()
        yield root
    finally:
        try:
            if created:
                shutil.rmtree(root)
        finally:
            if descriptor.value:
                kernel.LocalFree(descriptor)
            if user_string:
                kernel.LocalFree(ctypes.cast(user_string, p))

@contextlib.contextmanager
def fixture_dacl(path, *, null=False):
    """Change only the caller's disposable fixture DACL, preserving its owner."""
    from ctypes import wintypes as w
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    p = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p), ctypes.POINTER(p)]
    advapi.GetNamedSecurityInfoW.restype = w.DWORD
    advapi.SetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, p, p, p, p]
    advapi.SetNamedSecurityInfoW.restype = w.DWORD
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(p), ctypes.POINTER(w.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [p, ctypes.POINTER(w.BOOL), ctypes.POINTER(p), ctypes.POINTER(w.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = w.BOOL
    advapi.GetSecurityDescriptorControl.argtypes = [p, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = w.BOOL
    kernel.LocalFree.argtypes = [p]
    old_descriptor, old_dacl, replacement = p(), p(), p()
    control, revision = w.WORD(), w.DWORD()
    changed = False
    try:
        if advapi.GetNamedSecurityInfoW(str(path), 1, 4, None, None, ctypes.byref(old_dacl), None, ctypes.byref(old_descriptor)) != 0:
            raise AssertionError("FIXTURE_DACL_READ_FAILED")
        if not advapi.GetSecurityDescriptorControl(old_descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise AssertionError("FIXTURE_CONTROL_READ_FAILED")
        new_dacl = p()
        if not null:
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;FA;;;WD)", 1, ctypes.byref(replacement), None):
                raise AssertionError("FIXTURE_SDDL_FAILED")
            present, defaulted = w.BOOL(), w.BOOL()
            if not advapi.GetSecurityDescriptorDacl(replacement, ctypes.byref(present), ctypes.byref(new_dacl), ctypes.byref(defaulted)) or not present:
                raise AssertionError("FIXTURE_DACL_INVALID")
        if advapi.SetNamedSecurityInfoW(str(path), 1, 4 | 0x80000000, None, None, new_dacl, None) != 0:
            raise AssertionError("FIXTURE_DACL_SET_FAILED")
        changed = True
        yield
    finally:
        try:
            if changed:
                protection = 0x80000000 if control.value & 0x1000 else 0x20000000
                if advapi.SetNamedSecurityInfoW(str(path), 1, 4 | protection, None, None, old_dacl, None) != 0:
                    raise AssertionError("FIXTURE_DACL_RESTORE_FAILED")
        finally:
            if replacement.value:
                kernel.LocalFree(replacement)
            if old_descriptor.value:
                kernel.LocalFree(old_descriptor)

@unittest.skipUnless(os.name == "nt", "Native Win32 ABI/NTFS/DACL gate: requires Windows CI; Linux is not evidence")
class NativeWindowsClaimTests(unittest.TestCase):
    def setUp(self):
        if not _NATIVE_CHILD:
            return
        self.root = self.enterContext(new_private_native_fixture())
        # Every negative control first proves an admissible real native baseline.
        try:
            with m.windows_private_root(self.root):
                pass
        except m.ClaimError as error:
            raise AssertionError(str(error) + "; " + fixture_owner_diagnostic(self.root)) from error

    @isolated_native_test
    def test_native_bindings_private_claim_and_replay(self):
        receipt = m.claim(self.root, META)
        self.assertTrue(receipt["claimed"])
        self.assertTrue(receipt["audit_state_changed"])
        self.assertFalse(receipt["configuration_changed"])
        verify_private_fixture_acl(self.root / ("desktop-capacity-" + META["request_id"] + ".claim.json"), directory=False)
        with self.assertRaisesRegex(m.ClaimError, "REQUEST_ALREADY_CONSUMED"):
            m.claim(self.root, META)

    @isolated_native_test
    def test_native_concurrent_claim_exactly_one_winner(self):
        def attempt(_):
            try:
                return m.claim(self.root, META)["claimed"]
            except m.ClaimError as error:
                if str(error) != "REQUEST_ALREADY_CONSUMED_OR_UNCERTAIN":
                    raise
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))
        self.assertEqual(sum(results), 1)

    @isolated_native_test
    def test_native_null_and_broad_dacl_fail_without_claim(self):
        for null in (False, True):
            with self.subTest(null=null), fixture_dacl(self.root, null=null):
                reason = "NULL_DACL_REJECTED" if null else "DACL_OTHER_PRINCIPAL_REJECTED"
                with self.assertRaisesRegex(m.ClaimError, reason):
                    m.claim(self.root, META)
                self.assertEqual(list(self.root.iterdir()), [])

    @isolated_native_test
    def test_native_reparse_and_hardlink_are_rejected(self):
        alias = self.root / "alias"
        # No skip if CI lacks symlink capability: the mandatory Windows gate fails.
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(m.ClaimError, "REPARSE_REJECTED"):
            m.claim(alias, META)
        alias.unlink()
        first, second = self.root / "first", self.root / "second"
        first.write_bytes(b"fixture")
        os.link(first, second)
        with self.assertRaisesRegex(m.ClaimError, "HARDLINK"):
            m.ordinary(first, False)

    @isolated_native_test
    def test_native_open_directory_handles_prevent_rename(self):
        moved = self.root.with_name(self.root.name + "-moved")
        try:
            with m.windows_private_root(self.root):
                with self.assertRaises(OSError):
                    self.root.rename(moved)
            self.assertTrue(self.root.is_dir())
            self.assertFalse(moved.exists())
        finally:
            # Restore a failed negative control only after native handles close.
            if moved.exists() and not self.root.exists():
                moved.rename(self.root)

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--capacity-native-child":
        name = sys.argv[2]
        allowed = {name for name in vars(NativeWindowsClaimTests) if name.startswith("test_native_")}
        if os.name != "nt" or name not in allowed:
            raise SystemExit("FIXTURE_CHILD_SCOPE_INVALID")
        _NATIVE_CHILD = True
        with isolated_owner_context(json.loads(sys.argv[3])):
            result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([NativeWindowsClaimTests(name)]))
        print("CAPACITY_NATIVE_RECEIPT " + json.dumps({"test": name, "tests_run": result.testsRun, "skipped": len(result.skipped), "successful": result.wasSuccessful(), "token_isolated": True, "owner_restored": True, "security_invariants": True}, sort_keys=True))
        if not result.wasSuccessful() or result.testsRun != 1 or result.skipped:
            raise SystemExit(1)
    else:
        unittest.main()
