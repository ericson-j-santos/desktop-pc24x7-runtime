"""Fail-closed classification and backup inspection without any host mutation."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import orchestrator_supervisor_failure_inventory as inv


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.control = self.root / "data" / "control"
        self.control.mkdir(parents=True)
        self.now = time.time()

    def write_receipt(self, index, *, error="runtime refresh request expired", correlation=None,
                      target=None, host=None, raw=None):
        path = self.control / f"refresh-runtime.failed.{100+index}.json"
        payload = {"schema_version": 1, "target_host": host, "expected_sha": target,
                   "correlation_id": correlation, "failed_at_epoch": self.now - 10,
                   "error_type": "ValueError", "error": error}
        path.write_text(raw if raw is not None else json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def safe_read(path):
        raw = path.read_bytes()
        if len(raw) > 16384:
            raise ValueError("too large")
        value = json.loads(raw)
        info = path.stat()
        return value, "unused-digest", (info.st_size, info.st_mtime_ns)

    @staticmethod
    def safe_guard(path, *, directory):
        if path.is_symlink():
            raise ValueError("linked")
        info = path.lstat()
        if directory and not path.is_dir():
            raise ValueError("not dir")
        if not directory and not path.is_file():
            raise ValueError("not file")
        return info

    def scan(self, paths):
        return inv.classify_failures(sorted(paths), now=self.now, read_fn=self.safe_read,
                                     guard_fn=self.safe_guard)

    def test_empty_and_replay_are_safe(self):
        a = self.scan([])
        self.assertEqual(a, self.scan([]))
        self.assertFalse(a["original_exact_receipt_found"])
        self.assertFalse(a["recovery_allowed"])

    def test_classifies_27_receipts_without_disclosing_raw_errors(self):
        paths = [self.write_receipt(i, error="A secret-like string MUST NOT LEAK") for i in range(27)]
        result = self.scan(paths)
        self.assertEqual(result["failure_files_parsed"], 27)
        self.assertEqual(result["identity_groups"]["legacy_identity_missing"], 27)
        self.assertEqual(result["categories"]["unclassified_error"], 27)
        self.assertNotIn("MUST NOT LEAK", json.dumps(result))
        self.assertFalse(result["original_exact_receipt_found"])

    def test_only_exact_full_identity_is_original(self):
        paths = [self.write_receipt(1, correlation=inv.ORIGINAL_CORRELATION,
                                    target=inv.ORIGINAL_TARGET, host=inv.HOST)]
        result = self.scan(paths)
        self.assertTrue(result["original_exact_receipt_found"])
        self.assertEqual(result["categories"], {"refresh_request_expired": 1})
        self.assertFalse(result["recovery_allowed"])

    def test_identity_loss_does_not_attribute_original(self):
        paths = [self.write_receipt(1, target=inv.ORIGINAL_TARGET, host=inv.HOST),
                 self.write_receipt(2, correlation=inv.ORIGINAL_CORRELATION),
                 self.write_receipt(3, correlation="another-correlation")]
        result = self.scan(paths)
        self.assertEqual(result["identity_groups"], {
            "different_or_unrelated": 1, "original_partial": 1,
            "target_without_correlation": 1})
        self.assertFalse(result["original_exact_receipt_found"])

    def test_duplicate_exact_identity_not_marked_unique(self):
        paths = [self.write_receipt(i, correlation=inv.ORIGINAL_CORRELATION,
                                    target=inv.ORIGINAL_TARGET, host=inv.HOST) for i in (1, 2)]
        self.assertFalse(self.scan(paths)["original_exact_receipt_found"])

    def test_malformed_and_duplicate_fields_cannot_create_false_positive(self):
        paths = [self.write_receipt(1, raw='{"schema_version":1,"error":"oops"}'),
                 self.write_receipt(2, raw='not-json')]
        result = self.scan(paths)
        self.assertEqual(result["failure_files_invalid"], 2)
        self.assertFalse(result["classification_complete"])
        self.assertFalse(result["original_exact_receipt_found"])

    def test_rejected_oversized_or_redirected(self):
        real = self.write_receipt(1)
        linked = self.control / "refresh-runtime.failed.200.json"
        try:
            linked.symlink_to(real)
        except OSError:
            self.skipTest("Cannot make symlink on this platform")
        result = self.scan([linked])
        self.assertEqual(result["failure_files_invalid"], 1)
        self.assertFalse(result["classification_complete"])

    def test_limits_and_unexpected_file_name(self):
        p = self.write_receipt(1)
        with self.assertRaisesRegex(ValueError, "FAILURE_INVENTORY_LIMIT"):
            self.scan([p] * 65)
        with self.assertRaisesRegex(ValueError, "FAILURE_FILE_NAME_INVALID"):
            self.scan([self.root / "arbitrary.json"])

    def test_rollback_missing_is_blocked(self):
        a = inv.inspect_rollback_structure(self.root, guard_fn=self.safe_guard)
        self.assertFalse(a["rollback_restoration_tested"])
        self.assertFalse(a["recovery_allowed"])
        self.assertEqual(a["backup_structurally_complete_count"], 0)

    def test_structural_backup_is_not_a_tested_restore(self):
        backup = self.root / "data" / "runtime-backups" / ("1234567890-" + "a" * 12)
        (backup / "scripts").mkdir(parents=True)
        (backup / "orchestrator").mkdir(parents=True)
        (backup / "scripts" / "service_supervisor.py").write_text("pass\n")
        (backup / "orchestrator" / "__init__.py").write_text("pass\n")
        bootstrap = self.root / "bootstrap"
        bootstrap.mkdir()
        (bootstrap / "runtime_bootstrap_shim.py").write_text("pass\n")
        (bootstrap / "bootstrap-config.json").write_text("{}")
        a = inv.inspect_rollback_structure(self.root, guard_fn=self.safe_guard)
        self.assertEqual(a["backup_structurally_complete_count"], 1)
        self.assertTrue(a["stable_bootstrap_shim_present"])
        self.assertTrue(a["stable_bootstrap_config_present"])
        self.assertFalse(a["rollback_verified"])
        self.assertFalse(a["recovery_allowed"])

    def test_rollback_link_must_fail_closed(self):
        backups = self.root / "data" / "runtime-backups"
        backups.mkdir(parents=True)
        target = self.root / "placeholder"
        target.mkdir()
        link = backups / ("1234567890-" + "a" * 12)
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("Cannot make symlink on this platform")
        with self.assertRaises(ValueError):
            inv.inspect_rollback_structure(self.root, guard_fn=self.safe_guard)

if __name__ == "__main__":
    unittest.main()
