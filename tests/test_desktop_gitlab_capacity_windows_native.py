"""Native Windows fixture gates; Linux skips are explicit, not Windows evidence.

No production host collection or ACL repair. DACL mutations affect only fresh
TemporaryDirectory fixtures and are restored before cleanup. Windows CI must
execute these tests; API mocks are a separate test module.
"""
from __future__ import annotations
import concurrent.futures
import contextlib
import ctypes
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

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
        self.tmp = tempfile.TemporaryDirectory(prefix="capacity-native-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Every negative control first proves an admissible real native baseline.
        try:
            with m.windows_private_root(self.root):
                pass
        except m.ClaimError as error:
            raise AssertionError(str(error) + "; " + fixture_owner_diagnostic(self.root)) from error

    def tearDown(self):
        self.tmp.cleanup()

    def test_native_bindings_private_claim_and_replay(self):
        receipt = m.claim(self.root, META)
        self.assertTrue(receipt["claimed"])
        self.assertTrue(receipt["audit_state_changed"])
        self.assertFalse(receipt["configuration_changed"])
        with self.assertRaisesRegex(m.ClaimError, "REQUEST_ALREADY_CONSUMED"):
            m.claim(self.root, META)

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

    def test_native_null_and_broad_dacl_fail_without_claim(self):
        for null in (False, True):
            with self.subTest(null=null), fixture_dacl(self.root, null=null):
                reason = "NULL_DACL_REJECTED" if null else "DACL_OTHER_PRINCIPAL_REJECTED"
                with self.assertRaisesRegex(m.ClaimError, reason):
                    m.claim(self.root, META)
                self.assertEqual(list(self.root.iterdir()), [])

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
    unittest.main()
