"""Win32 guard decision tests with fake APIs: NOT ABI or physical Windows proof."""
import ctypes
from ctypes import wintypes
import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('capacity_claim_guard_tests', Path(__file__).resolve().parents[1] / 'scripts/desktop_gitlab_capacity_claim.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class FakePath:
    def __init__(self, text, parents=()):
        self.text, self.parents = text, parents
    def __str__(self):
        return self.text
    def is_absolute(self):
        return True
    @property
    def anchor(self):
        return 'C:\\'

class Function:
    def __init__(self, fn):
        self.fn = fn
    def __call__(self, *args):
        return self.fn(*args)

def pointer(value):
    return value.value if isinstance(value, ctypes.c_void_p) else value

class FakeWindows:
    """Fake success API, with per-handle owner/DACL and explicit failure switches."""
    CURRENT, SYSTEM, ADMIN, INSTALLER, OTHER = 101, 102, 103, 104, 999
    def __init__(self):
        self.closed, self.freed, self.buffers = [], [], []
        self.security = {}
        self.active_aces = []
        self.sid_values = {}
        self.next_handle = 10
        self.open_failure = False
        self.attributes = 0x10
        self.file_index = 42
        self.drive_type = 3
        self.filesystem = 'NTFS'
        self.security_failure = False
        self.functions = {}
    def __getattr__(self, name):
        if name not in self.functions:
            self.functions[name] = Function(getattr(self, '_' + name))
        return self.functions[name]
    def buffer(self, data):
        value = ctypes.create_string_buffer(data)
        self.buffers.append(value)
        return ctypes.addressof(value)
    def sid(self, value):
        value = pointer(value)
        return self.sid_values.get(value, value)
    def _GetCurrentProcess(self):
        return 1
    def _OpenProcessToken(self, process, access, out):
        out._obj.value = 2
        return 1
    def _GetTokenInformation(self, token, kind, buffer, size, needed):
        needed._obj.value = ctypes.sizeof(ctypes.c_void_p)
        if buffer is None:
            return 0
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0] = self.CURRENT
        return 1
    def _ConvertStringSidToSidW(self, value, out):
        out._obj.value = self.INSTALLER
        return 1
    def _EqualSid(self, left, right):
        return self.sid(left) == self.sid(right)
    def _IsWellKnownSid(self, value, kind):
        return self.sid(value) == {22:self.SYSTEM, 26:self.ADMIN}.get(kind)
    def _CreateFileW(self, path, access, sharing, security, disposition, flags, template):
        assert access == 0x20080 and sharing == 3 and disposition == 3 and flags == 0x02200000
        if self.open_failure:
            return ctypes.c_void_p(-1).value
        handle = self.next_handle
        self.next_handle += 1
        return handle
    def _GetFileInformationByHandle(self, handle, out):
        out._obj.attributes = self.attributes
        out._obj.index_low = self.file_index
        out._obj.index_high = 0
        return 1
    def _GetDriveTypeW(self, path):
        return self.drive_type
    def _GetVolumeInformationW(self, root, volume, volume_size, serial, component, flags, filesystem, filesystem_size):
        filesystem.value = self.filesystem
        if flags is not None:
            flags._obj.value = 0x8
        return 1
    def _GetSecurityInfo(self, handle, kind, flags, owner, group, dacl, sacl, descriptor):
        if self.security_failure:
            return 5
        owner_sid, entries = self.security.get(handle, (self.CURRENT, [(0, 0, 0x1F01FF, self.CURRENT)]))
        owner._obj.value = owner_sid
        self.active_aces = []
        if entries is not None:
            for ace_type, ace_flags, mask, sid in entries:
                address = self.buffer(struct.pack('<BBHI', ace_type, ace_flags, 16, mask) + bytes(8))
                self.sid_values[address + 8] = sid
                self.active_aces.append(address)
            dacl._obj.value = self.buffer(struct.pack('<BBHHH', 2, 0, 8 + 16 * len(entries), len(entries), 0))
        else:
            dacl._obj.value = None
        descriptor._obj.value = self.buffer(bytes(32))
        return 0
    def _GetAce(self, dacl, index, out):
        out._obj.value = self.active_aces[index]
        return 1
    def _CloseHandle(self, handle):
        self.closed.append(pointer(handle))
        return 1
    def _LocalFree(self, value):
        self.freed.append(pointer(value))
        return None

class WindowsGuardDecisionTests(unittest.TestCase):
    def run_guard(self, api):
        root = FakePath('C:\\audit', [FakePath('C:\\')])
        with patch.object(m.os, 'name', 'nt'), patch.object(m.ctypes, 'WinDLL', return_value=api, create=True), patch.object(m, 'ordinary', return_value=SimpleNamespace(st_ino=42)), patch.dict(sys.modules, {'msvcrt':SimpleNamespace(get_osfhandle=lambda fd:12)}):
            with m.windows_private_root(root) as verify:
                verify(7)
        self.assertEqual(api.closed, [11, 10, 2])
        self.assertGreaterEqual(len(api.freed), 4)

    def test_native_decision_path_positive_and_release(self):
        self.run_guard(FakeWindows())

    def test_trusted_os_aces_on_existing_root_and_claim_are_accepted(self):
        for sid in (FakeWindows.SYSTEM, FakeWindows.ADMIN, FakeWindows.INSTALLER):
            with self.subTest(sid=sid):
                api = FakeWindows()
                for handle in (11,12):
                    api.security[handle] = (api.CURRENT, [(0,0,0x1F01FF,api.CURRENT),(0,0,0x1F01FF,sid)])
                self.run_guard(api)

    def test_nonfixed_drive_and_non_ntfs_fail_closed(self):
        for field, value in [('drive_type',4),('drive_type',2),('drive_type',0),('filesystem','FAT32'),('filesystem','ReFS')]:
            with self.subTest(field=field, value=value):
                api = FakeWindows()
                setattr(api,field,value)
                with self.assertRaises(m.ClaimError):
                    self.run_guard(api)

    def test_root_and_claim_untrusted_writes_rejected(self):
        for handle in (11, 12):
            with self.subTest(handle=handle):
                api = FakeWindows()
                api.security[handle] = (api.CURRENT, [(0, 0, 0x1F01FF, api.OTHER)])
                with self.assertRaises(m.ClaimError):
                    self.run_guard(api)
                self.assertIn(2, api.closed)

    def test_null_empty_unknown_acl_and_owner_rejected(self):
        for owner, entries in [(101,None), (101,[]), (999,[(0,0,1,101)]), (101,[(9,0,1,101)])]:
            with self.subTest(owner=owner, entries=entries):
                api = FakeWindows()
                api.security[11] = (owner, entries)
                with self.assertRaises(m.ClaimError):
                    self.run_guard(api)
                self.assertIn(2, api.closed)

    def test_ancestor_mutation_grants_rejected(self):
        for mask in (0x10000,0x40,0x40000,0x80000,0x100,0x2,0x40000000,0x10000000):
            with self.subTest(mask=mask):
                api = FakeWindows()
                api.security[10] = (api.ADMIN, [(0,0,mask,api.OTHER)])
                with self.assertRaises(m.ClaimError):
                    self.run_guard(api)

    def test_ancestor_read_and_inherit_only_do_not_grant_mutation(self):
        for entries in ([(0,0,0x120089,999)],[(0,0x08,0x1F01FF,999)]):
            with self.subTest(entries=entries):
                api = FakeWindows()
                api.security[10] = (api.ADMIN, entries)
                self.run_guard(api)

    def test_handle_identity_reparse_and_errors_fail_closed(self):
        for field, value in [('file_index',43),('attributes',0x410),('attributes',0),('open_failure',True),('security_failure',True)]:
            with self.subTest(field=field):
                api = FakeWindows()
                setattr(api,field,value)
                with self.assertRaises(m.ClaimError):
                    self.run_guard(api)
                self.assertIn(2,api.closed)

if __name__ == '__main__':
    unittest.main()
