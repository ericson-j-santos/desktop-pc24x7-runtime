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
        with m.windows_private_root(self.root):
            pass

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
