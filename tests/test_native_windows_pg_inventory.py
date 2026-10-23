"""Synthetic controls only. No test invokes the real host collector."""
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / "scripts/native_windows_pg_inventory.py"
SPEC = importlib.util.spec_from_file_location("native_windows_pg_inventory", SOURCE)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def valid_env():
    return dict(zip(inventory.CI_KEYS, (
        "true", inventory.EXPECTED_REPOSITORY, "a" * 40, "b" * 40,
        inventory.EXPECTED_RUNNER, "Windows", "X64", "123", "1",
        "ericson-j-santos", "workflow_dispatch", "2.329.0", "true", "true", "true",
        inventory.datetime.now(inventory.timezone.utc).isoformat(),
    )))


class FakeMetadata:
    def os_version(self):
        return [{"major": 10, "minor": 0, "build": 22631}]

    def wsl(self):
        return [{"alias": "distro-1", "wsl_version": 2, "state": "unknown"}]

    def pg_services(self):
        return [{"alias": "pg-service-1", "state": "stopped"}]

    def pg_binaries(self):
        return [{"layout_major": 18, "component": "postgres", "file_version": "18.0.0.0"}]

    def fixed_disks(self):
        return [{"alias": "fixed-volume-1", "size_gib_floor": 100, "available_gib_floor": 20}]

    def tcp(self):
        return [{"port": 5432, "family": "ipv4", "bind": "loopback"}]


def result(factory=FakeMetadata, env=None, host=inventory.EXPECTED_HOST, platform="win32"):
    return inventory.report(env or valid_env(), host, platform, factory)


def ipv4_row(port=5432, address=b"\x7f\x00\x00\x01", state=2):
    return struct.pack("<I", state) + address + port.to_bytes(2, "big") + b"\0\0" + bytes(12)


def ipv6_row(port=5432, address=bytes(15) + b"\1", state=2):
    return address + bytes(4) + port.to_bytes(2, "big") + bytes(2) + bytes(24) + struct.pack("<II", state, 123)


class NativeInventoryTests(unittest.TestCase):
    def test_measured_is_not_qualified(self):
        data = result()
        self.assertEqual(data["status"], "measured")
        for field in ("database_target_qualified", "ready_for_installation", "systemd_verified",
                      "backup_restore_verified", "storage_durability_verified", "restart_verified"):
            self.assertIs(data[field], False)

    def test_host_rejected_before_factory(self):
        with patch.object(inventory, "WindowsMetadata") as factory:
            with self.assertRaises(inventory.InventoryBlocked):
                inventory.report(valid_env(), "other", "win32", factory)
            factory.assert_not_called()

    def test_expired_or_future_admission_rejected(self):
        for value in ("2000-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00", "no-date"):
            env = valid_env()
            env["INVENTORY_ADMITTED_AT"] = value
            with self.assertRaises(inventory.InventoryBlocked):
                result(env=env)

    def test_unknown_root_field_rejected(self):
        data = result()
        data["private"] = "secret"
        with self.assertRaises(inventory.InventoryBlocked):
            inventory.validate_report(data)

    def test_wrong_platform_rejected(self):
        with self.assertRaises(inventory.InventoryBlocked):
            result(platform="linux")

    def test_all_provenance_fields_fail_closed(self):
        for key in inventory.CI_KEYS:
            with self.subTest(key=key):
                env = valid_env()
                env[key] = ""
                with self.assertRaises(inventory.InventoryBlocked):
                    result(env=env)

    def test_other_runner_rejected(self):
        env = valid_env()
        env["RUNNER_NAME"] = "DESKTOP-PDQK954"
        with self.assertRaises(inventory.InventoryBlocked):
            result(env=env)

    def test_rerun_not_automatic_permission(self):
        env = valid_env()
        env["GITHUB_RUN_ATTEMPT"] = "2"
        with self.assertRaises(inventory.InventoryBlocked):
            result(env=env)

    def test_permission_error_is_unknown_not_empty(self):
        class Denied(FakeMetadata):
            def wsl(self):
                raise PermissionError("secret sentinel")
        section = result(Denied)["sections"]["wsl"]
        self.assertIsNone(section["items"])
        self.assertEqual(section["reason"], "access_denied")

    def test_empty_is_scoped_not_global_absence(self):
        class Empty(FakeMetadata):
            def wsl(self):
                return []
            def pg_services(self):
                return []
        data = result(Empty)
        self.assertEqual(data["scope"]["wsl"], "current_runner_hkcu_only")
        self.assertFalse(data["database_target_qualified"])

    def test_error_text_is_never_emitted(self):
        class Bad(FakeMetadata):
            def tcp(self):
                raise OSError("postgresql://private:secret@private/path")
        encoded = json.dumps(result(Bad))
        self.assertNotIn("private", encoded)
        self.assertNotIn("postgresql://", encoded)

    def test_unknown_backend_field_rejected(self):
        class Extra(FakeMetadata):
            def pg_services(self):
                return [{"alias": "pg-service-1", "state": "running", "commandline": "secret"}]
        with self.assertRaises(inventory.InventoryBlocked):
            result(Extra)

    def test_private_name_cannot_replace_alias(self):
        class Name(FakeMetadata):
            def wsl(self):
                return [{"alias": "private-name", "wsl_version": 2, "state": "unknown"}]
        with self.assertRaises(inventory.InventoryBlocked):
            result(Name)

    def test_binary_version_cannot_carry_text(self):
        class Version(FakeMetadata):
            def pg_binaries(self):
                return [{"layout_major": 18, "component": "postgres", "file_version": "secret"}]
        with self.assertRaises(inventory.InventoryBlocked):
            result(Version)

    def test_boolean_cannot_fake_version(self):
        class Wrong(FakeMetadata):
            def wsl(self):
                return [{"alias": "distro-1", "wsl_version": True, "state": "unknown"}]
        with self.assertRaises(inventory.InventoryBlocked):
            result(Wrong)

    def test_row_cap_rejected(self):
        class Many(FakeMetadata):
            def wsl(self):
                return super().wsl() * 65
        with self.assertRaises(inventory.InventoryBlocked):
            result(Many)

    def test_replay_has_same_read_only_semantics(self):
        self.assertEqual(result(), result())
        self.assertFalse(result()["configuration_changed"])

    def test_ipv4_loopback(self):
        rows = inventory.parse_tcp_table(struct.pack("<I", 1) + ipv4_row(), 2)
        self.assertEqual(rows, [{"port": 5432, "family": "ipv4", "bind": "loopback"}])

    def test_ipv6_loopback(self):
        rows = inventory.parse_tcp_table(struct.pack("<I", 1) + ipv6_row(), 23)
        self.assertEqual(rows, [{"port": 5432, "family": "ipv6", "bind": "loopback"}])

    def test_wildcard_and_other_bind(self):
        self.assertEqual(inventory.bind_class(bytes(4)), "wildcard")
        self.assertEqual(inventory.bind_class(bytes(16)), "wildcard")
        self.assertEqual(inventory.bind_class(b"\x0a\0\0\1"), "other")

    def test_no_other_ports_or_non_listeners(self):
        rows = ipv4_row(port=443) + ipv4_row(state=5)
        self.assertEqual(inventory.parse_tcp_table(struct.pack("<I", 2) + rows, 2), [])

    def test_tcp_truncation_is_not_empty(self):
        for data in (b"", struct.pack("<I", 1), struct.pack("<I", 4097)):
            with self.subTest(data=data):
                with self.assertRaises(inventory.InventoryBlocked):
                    inventory.parse_tcp_table(data, 2)

    def test_tcp_duplicate_endpoints_collapsed(self):
        row = ipv4_row()
        self.assertEqual(len(inventory.parse_tcp_table(struct.pack("<I", 2) + row + row, 2)), 1)

    def test_unknown_tcp_family_rejected(self):
        with self.assertRaises(inventory.InventoryBlocked):
            inventory.parse_tcp_table(bytes(4), 999)

    def test_sensitive_raw_identity_not_in_report(self):
        encoded = json.dumps(result())
        for text in (inventory.EXPECTED_HOST, inventory.EXPECTED_RUNNER, "C:\\", "BasePath",
                     "ImagePath", "DistributionName", "DATABASE_URL"):
            self.assertNotIn(text, encoded)

    def test_source_does_not_use_process_network_or_wsl_execution(self):
        import ast
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported = {n.names[0].name for n in ast.walk(tree) if isinstance(n, ast.Import)}
        self.assertFalse(imported & {"subprocess", "requests", "urllib", "psutil"})
        calls = {n.func.attr for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertFalse(calls & {"system", "popen", "connect", "create_connection", "run",
                                  "StartServiceW", "ControlService", "WslLaunch", "WslLaunchInteractive"})
        self.assertNotIn("wsl.exe", SOURCE.read_text(encoding="utf-8"))

    def test_output_is_fixed_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            canonical = Path(directory).resolve()
            with patch.object(inventory.Path, "cwd", return_value=canonical):
                inventory.write_report(result())
                file = canonical / inventory.OUTPUT
                first = file.read_bytes()
                with self.assertRaises(FileExistsError):
                    inventory.write_report(result())
                self.assertEqual(file.read_bytes(), first)

    def test_noncanonical_output_root_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            canonical = Path(directory).resolve()
            noncanonical = canonical / "unused" / ".."
            with patch.object(inventory.Path, "cwd", return_value=noncanonical):
                with self.assertRaisesRegex(inventory.InventoryBlocked, "OUTPUT_ROOT_REJECTED"):
                    inventory.write_report(result())
            self.assertFalse((canonical / inventory.OUTPUT.parent).exists())

    def test_tcp_scope_discloses_transient_metadata_without_emitting_owners(self):
        scope = result()["scope"]
        self.assertEqual(scope["tcp_snapshot"],
                         "all_listeners_transient_then_candidate_port_filter")
        self.assertIs(scope["tcp_owners_emitted"], False)
        self.assertIs(scope["tcp_owners_resolved"], False)
        self.assertNotIn("tcp_owners_collected", scope)

    def test_all_sections_are_required(self):
        data = result()
        del data["sections"]["wsl"]
        with self.assertRaises(inventory.InventoryBlocked):
            inventory.validate_report(data)


if __name__ == "__main__":
    unittest.main()
