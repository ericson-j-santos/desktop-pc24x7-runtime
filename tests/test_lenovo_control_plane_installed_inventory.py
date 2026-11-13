from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "lenovo_control_plane_installed_inventory.py"
SPEC = importlib.util.spec_from_file_location("lenovo_installed_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
SHA = "a" * 40


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "DesktopPC24x7" / "ControlPlaneWatchdog"
        self.release = self.root / "releases" / SHA
        self.scripts = self.release / "scripts"
        self.scripts.mkdir(parents=True)
        self.metadata_path = self.root / "metadata.json"
        self.watchdog_file = self.scripts / "desktop_control_plane_watchdog.py"
        self.uac_file = self.scripts / "desktop_control_plane_watchdog_uac_launcher.py"
        self.launcher_file = self.root / "run.py"
        self.watchdog_file.write_bytes(b"watchdog sample")
        self.uac_file.write_bytes(b"uac sample")
        self.launcher_file.write_bytes(b"launcher sample")
        self.metadata = {
            "host": module.HOST,
            "source_sha": SHA,
            "runtime_root": str(self.root),
            "release_root": str(self.release),
            "runner_home": "unused-secret-looking-value-must-not-leak",
        }
        self.save_metadata()

    def save_metadata(self):
        self.metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")

    def collect(self):
        return module.collect(self.root, host=module.HOST, runner=module.RUNNER)

    def reject(self, reason):
        with self.assertRaisesRegex(module.InventoryBlocked, reason):
            self.collect()

    def test_only_fixed_digest_and_sha_are_returned(self):
        out = self.collect()
        self.assertEqual(out["result"], "INSTALLED_INVENTORY_READ_ONLY")
        self.assertEqual(out["expected_installed_sha"], SHA)
        self.assertEqual(out["expected_watchdog_sha256"],
                         hashlib.sha256(b"watchdog sample").hexdigest())
        self.assertEqual(out["expected_uac_sha256"],
                         hashlib.sha256(b"uac sample").hexdigest())
        self.assertEqual(out["expected_launcher_sha256"],
                         hashlib.sha256(b"launcher sample").hexdigest())
        self.assertFalse(out["mutation_performed"])
        self.assertFalse(out["runner_health_proven"])
        self.assertFalse(out["upgrade_authorized"])
        self.assertNotIn("secret-looking-value", json.dumps(out))
        self.assertNotIn(str(self.root), json.dumps(out))

    def test_replay_is_deterministic_and_no_write(self):
        previous = {p: (p.stat().st_mtime_ns, p.read_bytes())
                    for p in (self.metadata_path, self.watchdog_file,
                              self.uac_file, self.launcher_file)}
        self.assertEqual(self.collect(), self.collect())
        current = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in previous}
        self.assertEqual(current, previous)

    def test_registered_launcher_locates_root_without_localappdata(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": "/some/other/service/profile"}):
            located = module.runtime_root_from_task({
                "launcher": str(self.launcher_file),
                "working_directory": str(self.root),
            })
        self.assertEqual(located, self.root)
        self.assertEqual(module.collect(located, host=module.HOST, runner=module.RUNNER), self.collect())

    def test_registered_launcher_must_have_exact_directory(self):
        other = Path(self.temp.name) / "foreign" / "run.py"
        other.parent.mkdir()
        other.write_text("ignored", encoding="utf-8")
        with self.assertRaisesRegex(module.InventoryBlocked, "task_launcher_path_invalid"):
            module.runtime_root_from_task({
                "launcher": str(other),
                "working_directory": str(other.parent),
            })

    def test_registered_launcher_workdir_mismatch_blocks(self):
        with self.assertRaisesRegex(module.InventoryBlocked, "task_launcher_path_invalid"):
            module.runtime_root_from_task({
                "launcher": str(self.launcher_file),
                "working_directory": str(self.scripts),
            })

    def test_registered_launcher_symlink_blocks(self):
        # Preserve the *correct* fixed name and directory. This must fail
        # because of the symlink, not accidentally because it was named alias.
        destination = self.root / "real-launcher.py"
        destination.write_bytes(self.launcher_file.read_bytes())
        self.launcher_file.unlink()
        try:
            self.launcher_file.symlink_to(destination)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable")
        with self.assertRaisesRegex(module.InventoryBlocked, "reparse_path_blocked"):
            module.runtime_root_from_task({
                "launcher": str(self.launcher_file),
                "working_directory": str(self.root),
            })

    def test_aligned_upgrade_profile_is_reported_without_mutation(self):
        self.assertTrue(module.upgrade_profile_root_aligned(
            self.root, str(self.root.parent.parent)))

    def test_local_system_profile_mismatch_is_not_upgrade_ready(self):
        unrelated = Path(self.temp.name) / "LocalSystem" / "AppData" / "Local"
        unrelated.mkdir(parents=True)
        self.assertFalse(module.upgrade_profile_root_aligned(self.root, str(unrelated)))

    def test_missing_runner_localappdata_never_claims_alignment(self):
        self.assertFalse(module.upgrade_profile_root_aligned(self.root, None))
        self.assertFalse(module.upgrade_profile_root_aligned(self.root, "relative/path"))

    def test_nonexistent_profile_cannot_claim_alignment(self):
        self.assertFalse(module.upgrade_profile_root_aligned(
            self.root, str(Path(self.temp.name) / "unknown")))

    def test_missing_metadata_blocks(self):
        self.metadata_path.unlink()
        self.reject("file_read_unavailable")

    def test_wrong_physical_host_blocks(self):
        with self.assertRaisesRegex(module.InventoryBlocked, "physical_host_mismatch"):
            module.collect(self.root, host="NOTERI", runner=module.RUNNER)

    def test_wrong_runner_blocks(self):
        with self.assertRaisesRegex(module.InventoryBlocked, "runner_identity_mismatch"):
            module.collect(self.root, host=module.HOST, runner="OTHER")

    def test_bad_installed_sha_blocks(self):
        self.metadata["source_sha"] = "not-a-sha"
        self.save_metadata()
        self.reject("installed_source_sha_invalid")

    def test_foreign_metadata_host_blocks(self):
        self.metadata["host"] = "DESKTOP-PDQK954"
        self.save_metadata()
        self.reject("metadata_host_mismatch")

    def test_foreign_release_root_blocks(self):
        self.metadata["release_root"] = str(self.root / "another")
        self.save_metadata()
        self.reject("metadata_root_mismatch")

    def test_symlink_file_blocks(self):
        self.watchdog_file.unlink()
        try:
            self.watchdog_file.symlink_to(self.launcher_file)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable on this platform")
        self.reject("reparse_path_blocked")

    def test_symlink_release_directory_blocks(self):
        alternate = self.root / "alternate"
        self.release.rename(alternate)
        try:
            self.release.symlink_to(alternate, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable on this platform")
        self.reject("reparse_path_blocked")

    def test_missing_launcher_blocks(self):
        self.launcher_file.unlink()
        self.reject("file_read_unavailable")

    def test_oversized_launcher_blocks(self):
        self.launcher_file.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        self.reject("file_type_or_size_invalid")

    def test_metadata_is_not_allowed_to_be_unparseable(self):
        self.metadata_path.write_text("{invalid", encoding="utf-8")
        self.reject("metadata_invalid")

    def test_file_mutation_during_double_read_blocks(self):
        original = Path.read_bytes
        calls = [0]

        def fake_read(path):
            data = original(path)
            if path == self.watchdog_file:
                calls[0] += 1
                return data if calls[0] == 1 else b"unexpected bytes"
            return data

        with patch.object(Path, "read_bytes", fake_read):
            self.reject("file_changed_during_readback")

    def test_mutation_after_first_file_hash_is_rejected(self):
        """Prevent a mixed-generation inventory when a release changes between files."""
        original = module._read_stable
        changed = [False]

        def interleaved(path, root, limit):
            data = original(path, root, limit)
            if path == self.uac_file and not changed[0]:
                changed[0] = True
                self.watchdog_file.write_bytes(b"new watchdog installed during scan")
            return data

        with patch.object(module, "_read_stable", side_effect=interleaved):
            self.reject("file_changed_during_inventory")
        self.assertTrue(changed[0])

    def test_context_guard_blocks_without_actions(self):
        stdout = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=True):
            with contextlib.redirect_stdout(stdout):
                code = module.main()
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(stdout.getvalue())["result"], "BLOCKED")
        self.assertNotIn(str(self.root), stdout.getvalue())

    def test_irrelevant_file_does_not_change_inventory(self):
        baseline = self.collect()
        (self.root / "random-other-file.txt").write_text("ignored", encoding="utf-8")
        self.assertEqual(baseline, self.collect())


if __name__ == "__main__":
    unittest.main()
