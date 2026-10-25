"""Synthetic-only readback controls; never instantiate a physical backend."""
import ast
import ctypes
import importlib.util
import json
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / "scripts/native_windows_pg_readback.py"
SPEC = importlib.util.spec_from_file_location("native_windows_pg_readback", SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def valid_env():
    return dict(zip(m.base.CI_KEYS, (
        "true", m.base.EXPECTED_REPOSITORY, "a" * 40, "b" * 40,
        m.base.EXPECTED_RUNNER, "Windows", "X64", "123", "1",
        "ericson-j-santos", "workflow_dispatch", "2.338.0", "true", "true", "true",
        m.base.datetime.now(m.base.timezone.utc).isoformat(),
        "",
    )))


def receipt(alias):
    contract = dict((a, c) for a, _, c in m.RECEIPTS)[alias]
    return {"contract": contract, "generated_at": "2026-09-16T12:00:00+00:00", "ready": True,
            "sql_event_readback": True, "sql_continuation_readback": True,
            "negative_control_passed": True, "event_id": "PRIVATE_EVENT_SENTINEL",
            "restart": {"persistent": True},
            "backup_restore": {"restore_verified": True, "backup_size": 49965,
                               "backup_sha256": "a" * 64,
                               "backup_file": r"C:\PRIVATE_PATH_SENTINEL\backup.dump"},
            "unexpected": "PRIVATE_SECRET_SENTINEL"}


class Fake:
    def tcp_5432(self):
        return [("ipv4", "loopback", 987654321), ("ipv6", "wildcard", 987654322)]

    def process_metadata(self, pid):
        return ("postgres-image", 42) if pid == 987654321 else ("wsl-related-image", 43)

    def read_legacy_receipt(self, filename):
        alias = next(a for a, name, _ in m.RECEIPTS if name == filename)
        return json.dumps(receipt(alias)).encode()


def result(factory=Fake, env=None, host=m.base.EXPECTED_HOST):
    return m.report(env or valid_env(), host, "win32", factory)


def row4(pid=987654321, port=5432, state=2):
    return struct.pack("<I", state) + b"\x7f\0\0\1" + port.to_bytes(2, "big") + bytes(10) + struct.pack("<I", pid)


def row6(pid=987654321, port=5432, state=2):
    return bytes(15) + b"\1" + bytes(4) + port.to_bytes(2, "big") + bytes(26) + struct.pack("<II", state, pid)



class ReceiptApiFake:
    """All Win32 entry points are fake; no filesystem or process is accessed."""
    def __init__(self, **options):
        self.options = options
        self.calls = []
        self.opened_path = ""
        self.info_calls = 0
        self.data = b'{"contract":"synthetic"}'
        self.folder_buffer = ctypes.create_unicode_buffer(options.get("folder", r"C:\runner-profile"))

    def known(self, guid, flags, token, output):
        self.calls.append(("known", flags, token))
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = ctypes.addressof(self.folder_buffer)
        return self.options.get("known_error", 0)

    def create(self, path, rights, share, security, disposition, flags, template):
        self.calls.append(("create", rights, share, disposition, flags))
        self.opened_path = path
        return ctypes.c_void_p(-1).value if self.options.get("create_fail") else 12

    def info(self, handle, pointer):
        self.info_calls += 1
        self.calls.append(("info", self.info_calls))
        if self.options.get("info_fail_at") == self.info_calls:
            return 0
        values = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 13)).contents
        values[0] = self.options.get("attributes", 0)
        values[5] = 100 + (1 if self.info_calls == 2 and self.options.get("mtime_changed") else 0)
        values[7] = 1
        values[8] = 0
        values[9] = self.options.get("size", len(self.data)) + (
            1 if self.info_calls == 2 and self.options.get("size_changed") else 0)
        values[10] = self.options.get("links", 1)
        values[11], values[12] = 0, 5
        return 1

    def final(self, handle, buffer, capacity, flags):
        self.calls.append(("final", flags))
        if self.options.get("final_fail"):
            return 0
        if self.options.get("final_truncated"):
            return capacity
        path = r"C:\other\file.json" if self.options.get("path_changed") else self.opened_path
        buffer.value = "\\\\?\\" + m.ntpath.normpath(path)
        return len(buffer.value)

    def read(self, handle, buffer, capacity, count, overlapped):
        self.calls.append(("read", capacity))
        if self.options.get("read_fail"):
            return 0
        ctypes.memmove(buffer, self.data, len(self.data))
        ctypes.cast(count, ctypes.POINTER(ctypes.c_uint32)).contents.value = (
            len(self.data) - 1 if self.options.get("short_read") else len(self.data))
        return 1

    def invoke(self, filename="e2e-last.json"):
        obj = m.WindowsOwnerMetadata.__new__(m.WindowsOwnerMetadata)
        obj.kernel = object()
        functions = {
            "SHGetKnownFolderPath": self.known,
            "CoTaskMemFree": lambda p: self.calls.append(("free-folder",)),
            "GetDriveTypeW": lambda p: self.options.get("drive_type", 3),
            "GetFileAttributesW": lambda p: self.options.get("preflight_attributes",
                                                          self.options.get("attributes", 0)),
            "CreateFileW": self.create, "GetFileInformationByHandle": self.info,
            "GetFinalPathNameByHandleW": self.final, "ReadFile": self.read,
            "CloseHandle": lambda h: self.calls.append(("close", h)),
        }
        obj.fn = lambda dll, name, returns, args: functions[name]
        with patch.object(m.ctypes, "WinDLL", lambda *a, **kw: object(), create=True), \
             patch.object(m.ctypes, "WinError", lambda _: OSError("PRIVATE_ERROR_SENTINEL"), create=True), \
             patch.object(m.ctypes, "get_last_error", lambda: 5, create=True), \
             patch.object(m.base.WindowsMetadata, "safe_metadata_path"):
            return obj.read_legacy_receipt(filename)


class ReadbackTests(unittest.TestCase):
    def test_measured_does_not_qualify_database(self):
        value = result()
        self.assertEqual(value["status"], "measured")
        for key in m.FALSE_FIELDS:
            self.assertIs(value[key], False)

    def test_provenance_rejected_before_backend(self):
        with patch.object(m, "WindowsOwnerMetadata") as factory:
            with self.assertRaises(m.base.InventoryBlocked):
                m.report(valid_env(), "WRONG_HOST", "win32", factory)
            factory.assert_not_called()

    def test_every_provenance_field_remains_required(self):
        for key in (name for name in m.base.CI_KEYS
                    if name != "INVENTORY_DISPATCH_PROVENANCE"):
            env = valid_env()
            env[key] = ""
            with self.subTest(key=key), self.assertRaises(m.base.InventoryBlocked):
                result(env=env)

    def test_ipv4_owner_pid_is_parsed_only_transiently(self):
        self.assertEqual(m.parse_owners(struct.pack("<I", 1) + row4(), 2),
                         [("ipv4", "loopback", 987654321)])

    def test_ipv6_owner_pid_is_parsed_only_transiently(self):
        self.assertEqual(m.parse_owners(struct.pack("<I", 1) + row6(), 23),
                         [("ipv6", "loopback", 987654321)])

    def test_no_process_probe_for_other_ports_or_nonlisteners(self):
        class NoOwners(Fake):
            def tcp_5432(self):
                return m.parse_owners(struct.pack("<I", 2) + row4(port=55432) + row4(state=5), 2)
            def process_metadata(self, pid):
                raise AssertionError("must not query a non-candidate process")
        self.assertEqual(result(NoOwners)["listener_owners_5432"]["items"], [])

    def test_same_bind_different_owners_are_not_collapsed(self):
        rows = m.parse_owners(struct.pack("<I", 2) + row4(pid=11) + row4(pid=12), 2)
        self.assertEqual(len(rows), 2)

    def test_duplicate_endpoint_pid_is_collapsed(self):
        self.assertEqual(len(m.parse_owners(struct.pack("<I", 2) + row4() + row4(), 2)), 1)

    def test_invalid_tcp_buffers_rejected(self):
        for raw, family in ((b"", 2), (struct.pack("<I", 1), 2),
                            (struct.pack("<I", 4097), 23), (bytes(4), 99)):
            with self.subTest(family=family), self.assertRaises(m.base.InventoryBlocked):
                m.parse_owners(raw, family)

    def test_owner_cap_is_enforced(self):
        raw = struct.pack("<I", 17) + b"".join(row4(pid=i + 1) for i in range(17))
        with self.assertRaises(m.base.InventoryBlocked):
            m.parse_owners(raw, 2)

    def test_image_classification_is_exact_basename_only(self):
        cases = {r"C:\custom\postgres.exe": "postgres-image",
                 r"C:\custom\POSTGRES.EXE": "postgres-image",
                 r"C:\custom\evil-postgres.exe": "other-image",
                 r"C:\custom\wslrelay.exe": "wsl-related-image",
                 r"C:\custom\com.docker.backend.exe": "container-related-image",
                 r"C:\custom\svchost.exe": "windows-host-image",
                 r"C:\custom\secret.exe": "other-image"}
        for path, category in cases.items():
            self.assertEqual(m.image_hint(path), category)

    def test_invalid_image_metadata_rejected(self):
        for value in ("", "x" * 32769, "a\0b", None):
            with self.assertRaises(m.base.InventoryBlocked):
                m.image_hint(value)

    def test_access_denied_is_unknown_without_raw_error(self):
        class Denied(Fake):
            def process_metadata(self, pid):
                raise PermissionError("PRIVATE_SECRET_SENTINEL")
        value = result(Denied)
        self.assertEqual(value["status"], "partial")
        self.assertTrue(all(x["owner_hint"] == "unknown" for x in value["listener_owners_5432"]["items"]))
        self.assertNotIn("PRIVATE_SECRET_SENTINEL", json.dumps(value))

    def test_pid_reuse_changes_creation_time_and_is_unknown(self):
        class Reused(Fake):
            def __init__(self):
                self.calls = {}
            def process_metadata(self, pid):
                self.calls[pid] = self.calls.get(pid, 0) + 1
                return "postgres-image", self.calls[pid]
        self.assertTrue(all(x["attribution"] == "process_changed"
                            for x in result(Reused)["listener_owners_5432"]["items"]))

    def test_disappearing_process_is_unknown(self):
        class Gone(Fake):
            def __init__(self):
                self.calls = {}
            def process_metadata(self, pid):
                self.calls[pid] = self.calls.get(pid, 0) + 1
                if self.calls[pid] > 1:
                    raise OSError("PRIVATE_SECRET_SENTINEL")
                return super().process_metadata(pid)
        self.assertEqual(result(Gone)["status"], "partial")

    def test_changed_tcp_snapshot_releases_no_owner_attribution(self):
        class Changed(Fake):
            def __init__(self):
                self.calls = 0
            def tcp_5432(self):
                self.calls += 1
                return super().tcp_5432() if self.calls == 1 else []
        section = result(Changed)["listener_owners_5432"]
        self.assertEqual(section, {"status": "unavailable", "reason": "snapshot_changed", "items": None})

    def test_raw_process_and_receipt_identity_never_emitted(self):
        value = result()
        text = json.dumps(value)
        for sentinel in ("987654321", "987654322", "PRIVATE_",
                         "C:\\", m.base.EXPECTED_HOST, m.base.EXPECTED_RUNNER):
            self.assertNotIn(sentinel, text)
        def keys(item):
            if isinstance(item, dict):
                for key, nested in item.items():
                    yield key
                    yield from keys(nested)
            elif isinstance(item, list):
                for nested in item:
                    yield from keys(nested)
        self.assertFalse(set(keys(value)) & {"event_id", "backup_file", "backup_sha256",
                                            "pid", "path", "commandline", "environment"})

    def test_only_two_fixed_receipts_are_requested(self):
        seen = []
        def reader(name):
            seen.append(name)
            raise FileNotFoundError()
        self.assertEqual([r["status"] for r in m.receipt_projection(reader)], ["missing", "missing"])
        self.assertEqual(seen, ["e2e-last.json", "resilience-last.json"])

    def test_receipt_path_or_hash_is_not_followed_or_emitted(self):
        value = result()["legacy_receipts"][1]
        self.assertTrue(value["backup_hash_recorded"])
        self.assertEqual(value["recorded_backup_bytes"], 49965)
        self.assertNotIn("a" * 64, json.dumps(value))

    def test_boolean_strings_are_not_accepted_as_proof(self):
        data = receipt("legacy-e2e")
        data["ready"] = "true"
        with self.assertRaises(ValueError):
            m.sanitize_receipt(json.dumps(data).encode(), "legacy-e2e", data["contract"])

    def test_receipt_unknown_fields_are_omitted(self):
        data = receipt("legacy-e2e")
        value = m.sanitize_receipt(json.dumps(data).encode(), "legacy-e2e", data["contract"])
        self.assertNotIn("unexpected", value)
        self.assertNotIn("PRIVATE", json.dumps(value))

    def test_receipt_contract_timestamp_duplicates_and_limits_fail_closed(self):
        valid = receipt("legacy-e2e")
        bad = [b"[]", b"{}", b"x" * 65537, b'{"contract":1,"contract":2}',
               json.dumps({**valid, "contract": "other"}).encode(),
               json.dumps({**valid, "generated_at": "not-a-date"}).encode(),
               json.dumps({**valid, "generated_at": "2026-09-16T12:00:00"}).encode(),
               json.dumps({**valid, "generated_at": "2099-09-16T12:00:00+00:00"}).encode(),
               json.dumps({**valid, "generated_at": "0001-01-01T00:00:00+23:59"}).encode(),
               json.dumps({**valid, "generated_at": "9999-12-31T23:59:59-23:59"}).encode()]
        for raw in bad:
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                m.sanitize_receipt(raw, "legacy-e2e", valid["contract"])

    def test_missing_receipt_is_not_absence_of_database(self):
        class Missing(Fake):
            def read_legacy_receipt(self, filename):
                raise FileNotFoundError()
        value = result(Missing)
        self.assertEqual(value["status"], "partial")
        self.assertFalse(value["database_target_qualified"])

    def test_historical_false_remains_false_not_current_health(self):
        data = receipt("legacy-resilience")
        data["ready"] = False
        value = m.sanitize_receipt(json.dumps(data).encode(), "legacy-resilience", data["contract"])
        self.assertIs(value["historical_ready"], False)

    def test_unknown_report_field_and_raw_path_rejected(self):
        value = result()
        value["raw_path"] = "PRIVATE"
        with self.assertRaises(m.base.InventoryBlocked):
            m.validate_report(value)

    def test_unknown_listener_field_rejected(self):
        value = result()
        value["listener_owners_5432"]["items"][0]["pid"] = 987654321
        with self.assertRaises(m.base.InventoryBlocked):
            m.validate_report(value)

    def test_false_positive_qualified_flag_rejected(self):
        value = result()
        value["database_target_qualified"] = True
        with self.assertRaises(m.base.InventoryBlocked):
            m.validate_report(value)

    def test_no_subprocess_database_wsl_service_or_write_api(self):
        source = SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse(imports & {"subprocess", "requests", "urllib", "psutil"})
        for forbidden in ("WriteFile", "StartServiceW", "ControlService", "WslLaunch",
                          "SeDebugPrivilege", "ReadProcessMemory", "QueryServiceConfig",
                          "wsl.exe", "runtime.env", "open_process(0x1F"):
            self.assertNotIn(forbidden, source)
        self.assertIn("open_process(0x1000, False, pid)", source)
        self.assertIn("safe_metadata_path(path)", source)
        self.assertIn("GetFinalPathNameByHandleW", source)
        self.assertIn("PROFILE_NOT_FIXED_VOLUME", source)
        self.assertIn("before[10] != 1", source)
        self.assertIn("ctypes.c_void_p(-1).value", source)

    def test_process_handle_is_closed_on_success_or_query_failure(self):
        for fail, reported_length in ((False, None), (True, None), (False, 0), (False, 32768)):
            closed, opened = [], []
            obj = m.WindowsOwnerMetadata.__new__(m.WindowsOwnerMetadata)
            obj.kernel = object()
            def open_process(rights, inherit, pid):
                opened.append((rights, inherit, pid))
                return 12
            def image(handle, flags, buffer, size):
                self.assertEqual(flags, 0)
                if fail:
                    return 0
                buffer.value = r"C:\custom\postgres.exe"
                ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32)).contents.value = (
                    len(buffer.value) if reported_length is None else reported_length)
                return 1
            def times(handle, created, ended, kernel, user):
                ctypes.cast(created, ctypes.POINTER(ctypes.c_uint64)).contents.value = 42
                return 1
            functions = {"OpenProcess": open_process, "QueryFullProcessImageNameW": image,
                         "GetProcessTimes": times, "CloseHandle": lambda h: closed.append(h)}
            obj.fn = lambda dll, name, returns, args: functions[name]
            with patch.object(m.ctypes, "WinError", lambda _: OSError("hidden"), create=True), \
                 patch.object(m.ctypes, "get_last_error", lambda: 5, create=True):
                if fail:
                    with self.assertRaises(OSError):
                        obj.process_metadata(123)
                elif reported_length in (0, 32768):
                    with self.assertRaises(m.base.InventoryBlocked):
                        obj.process_metadata(123)
                else:
                    self.assertEqual(obj.process_metadata(123), ("postgres-image", 42))
            self.assertEqual(opened, [(0x1000, False, 123)])
            self.assertEqual(closed, [12])

    def test_fixed_receipt_read_uses_readonly_existing_file_api(self):
        fake = ReceiptApiFake()
        self.assertEqual(fake.invoke(), fake.data)
        self.assertIn(("known", 0x4000, None), fake.calls)
        self.assertIn(("create", 0x80000000, 7, 3, 0x00300000), fake.calls)
        self.assertEqual(fake.calls.count(("close", 12)), 1)
        self.assertEqual(fake.calls.count(("free-folder",)), 1)

    def test_final_path_mismatch_or_truncation_blocks_before_read(self):
        for option in ("path_changed", "final_fail", "final_truncated"):
            fake = ReceiptApiFake(**{option: True})
            with self.subTest(option=option), self.assertRaises(m.base.InventoryBlocked):
                fake.invoke()
            self.assertFalse(any(call[0] == "read" for call in fake.calls))
            self.assertEqual(fake.calls.count(("close", 12)), 1)

    def test_placeholder_or_special_file_rejected_before_open(self):
        for bit in (0x400, 0x10, 0x1000, 0x40000, 0x400000):
            fake = ReceiptApiFake(attributes=bit)
            with self.subTest(bit=bit), self.assertRaises(m.base.InventoryBlocked):
                fake.invoke()
            self.assertFalse(any(c[0] in ("create", "read", "close") for c in fake.calls))

    def test_new_placeholder_hardlinks_and_oversize_block_before_read(self):
        cases = [{"preflight_attributes": 0, "attributes": bit}
                 for bit in (0x400, 0x10, 0x1000, 0x40000, 0x400000)]
        cases += [{"links": 2}, {"size": 65537}, {"size": 1}]
        for options in cases:
            fake = ReceiptApiFake(**options)
            with self.subTest(options=options), self.assertRaises(m.base.InventoryBlocked):
                fake.invoke()
            self.assertFalse(any(call[0] == "read" for call in fake.calls))
            self.assertEqual(fake.calls.count(("close", 12)), 1)

    def test_size_mtime_or_short_read_change_is_not_silent_success(self):
        for option in ("size_changed", "mtime_changed", "short_read"):
            fake = ReceiptApiFake(**{option: True})
            with self.subTest(option=option), self.assertRaises(m.base.InventoryBlocked):
                fake.invoke()
            self.assertEqual(sum(call[0] == "read" for call in fake.calls), 1)
            self.assertEqual(fake.calls.count(("close", 12)), 1)

    def test_file_handle_closed_after_info_and_read_errors(self):
        for options in ({"info_fail_at": 1}, {"info_fail_at": 2}, {"read_fail": True}):
            fake = ReceiptApiFake(**options)
            with self.subTest(options=options), self.assertRaises(OSError):
                fake.invoke()
            self.assertEqual(fake.calls.count(("close", 12)), 1)

    def test_invalid_file_handle_is_never_used_or_closed(self):
        fake = ReceiptApiFake(create_fail=True)
        with self.assertRaises(OSError):
            fake.invoke()
        self.assertFalse(any(c[0] in ("read", "info", "final", "close") for c in fake.calls))
        self.assertEqual(fake.calls.count(("free-folder",)), 1)

    def test_unavailable_profile_or_file_metadata_blocks_before_open(self):
        cases = (({"folder": r"\\server\share"}, m.base.InventoryBlocked),
                 ({"drive_type": 4}, m.base.InventoryBlocked),
                 ({"known_error": 1}, m.base.InventoryBlocked),
                 ({"preflight_attributes": 0xFFFFFFFF}, OSError))
        for options, expected in cases:
            fake = ReceiptApiFake(**options)
            with self.subTest(options=options), self.assertRaises(expected):
                fake.invoke()
            self.assertFalse(any(c[0] == "create" for c in fake.calls))
            self.assertEqual(fake.calls.count(("free-folder",)), 1)

    def test_no_arbitrary_receipt_filename_reaches_windows_apis(self):
        fake = ReceiptApiFake()
        with self.assertRaises(m.base.InventoryBlocked):
            fake.invoke("../credentials.json")
        self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()

