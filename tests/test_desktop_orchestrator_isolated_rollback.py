"""Isolated filesystem E2E: durable code snapshot and exact restore, no live service."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import desktop_orchestrator_isolated_rollback as m


class RollbackContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "runtime"
        (self.root / "orchestrator").mkdir(parents=True)
        (self.root / "scripts").mkdir()
        (self.root / "data" / "runtime-backups").mkdir(parents=True)
        (self.root / "orchestrator" / "__init__.py").write_text("OLD = True\n")
        (self.root / "orchestrator" / "worker_agent.py").write_text("SAFE = True\n")
        (self.root / "scripts" / "service_supervisor.py").write_text("RUNNING = True\n")
        (self.root / "scripts" / "module.py").write_text("VERSION = 1\n")
        self.run_id = "38298888777"
        self.attempt = "1"
        self.before_calls = 0

    def before(self):
        self.before_calls += 1
        return {"installed_source_sha": m.EXPECTED_INSTALLED_SHA,
                "live_state_consistent": True, "pending_refresh_present": False}

    def run_once(self):
        return m.snapshot_and_test(self.root, run_id=self.run_id, attempt=self.attempt,
                                   expected_installed_sha=m.EXPECTED_INSTALLED_SHA,
                                   before_fn=self.before)

    def test_snapshot_and_real_isolated_restore_positive_then_replay(self):
        original = m.code_manifest(self.root)
        first = self.run_once()
        self.assertTrue(first["local_snapshot_present"])
        self.assertTrue(first["isolated_restore_verified"])
        self.assertFalse(first["current_service_rollback_verified"])
        self.assertFalse(first["recovery_allowed"])
        self.assertFalse(first["configs_or_secrets_read"])
        self.assertFalse(first["replayed"])
        self.assertEqual(first["snapshot_file_count"], 4)
        self.assertEqual(m.code_manifest(self.root), original)
        snapshot = self.root / "data/runtime-backups" / f"verified-code-{m.EXPECTED_INSTALLED_SHA[:12]}-{self.run_id}-{self.attempt}"
        self.assertTrue(snapshot.is_dir())
        self.assertEqual(m.code_manifest(snapshot), original)
        self.assertEqual(json.loads((snapshot / m.MANIFEST).read_text())["runtime_sha"], m.EXPECTED_INSTALLED_SHA)
        second = self.run_once()
        self.assertEqual(second["backup_sha256"], first["backup_sha256"])
        self.assertTrue(second["replayed"])
        self.assertEqual(self.before_calls, 4)
        self.assertEqual(len(list((self.root / "data/runtime-backups").glob("verified-code-*"))), 1)

    def test_source_sha_mismatch_prevents_any_file_change(self):
        with self.assertRaisesRegex(m.RollbackError, "EXPECTED_VERSION_INVALID"):
            m.snapshot_and_test(self.root, run_id=self.run_id, attempt=self.attempt,
                                expected_installed_sha="b" * 40, before_fn=self.before)
        self.assertEqual(list((self.root / "data/runtime-backups").iterdir()), [])

    def test_pending_refresh_blocks_snapshot(self):
        def pending():
            return {"installed_source_sha": m.EXPECTED_INSTALLED_SHA,
                    "live_state_consistent": True, "pending_refresh_present": True}
        with self.assertRaisesRegex(m.RollbackError, "RUNTIME_PRECONDITION_MISMATCH"):
            m.snapshot_and_test(self.root, run_id=self.run_id, attempt=self.attempt,
                                expected_installed_sha=m.EXPECTED_INSTALLED_SHA,
                                before_fn=pending)
        self.assertEqual(list((self.root / "data/runtime-backups").iterdir()), [])

    def test_bad_run_identifier_rejected(self):
        for value in ["", "0", "1", "../unsafe", "0012", "-123", "1;bad", "99999999999999999999999999"]:
            with self.subTest(run_id=value), self.assertRaises(m.RollbackError):
                m.snapshot_and_test(self.root, run_id=value, attempt="1",
                                    expected_installed_sha=m.EXPECTED_INSTALLED_SHA,
                                    before_fn=self.before)

    def test_link_in_runtime_code_blocks_unsafe_copy(self):
        file = self.root / "scripts" / "external.py"
        try:
            file.symlink_to(self.root / "orchestrator" / "__init__.py")
        except OSError:
            self.skipTest("Symlink privileges unavailable")
        with self.assertRaisesRegex(m.RollbackError, "CODE_PATH_REDIRECTED"):
            self.run_once()

    def test_refuse_unknown_or_sensitive_file_name(self):
        for name in ["token.json", "auth.pem", ".env", "unknown.exe"]:
            with self.subTest(name=name):
                file = self.root / "scripts" / name
                file.write_text("SENSITIVE CONTENT MUST NOT BE READ")
                with self.assertRaisesRegex(m.RollbackError, "CODE_FILE_NOT_ALLOWLISTED"):
                    m.code_manifest(self.root)
                file.unlink()

    def test_only_skip_python_cache_not_code(self):
        cache = self.root / "scripts" / "__pycache__"
        cache.mkdir()
        (cache / "module.pyc").write_bytes(b"not source")
        self.assertEqual(m.code_manifest(self.root)["count"], 4)

    def test_restore_tamper_detected(self):
        manifest = m.code_manifest(self.root)
        src_copy = m._copy_code
        def corrupt(source, dest, expected):
            src_copy(source, dest, expected)
            (dest / "scripts/service_supervisor.py").write_text("MODIFIED AFTER COPY")
        with patch.object(m, "_copy_code", side_effect=corrupt):
            with self.assertRaisesRegex(m.RollbackError, "ISOLATED_RESTORE_MISMATCH"):
                m.validate_isolated_restore(self.root, manifest, work_parent=self.root / "data/runtime-backups")

    def test_existing_snapshot_corruption_rejected_on_replay(self):
        self.run_once()
        snap = next((self.root / "data/runtime-backups").glob("verified-code-*"))
        (snap / "scripts/service_supervisor.py").write_text("TAMPER")
        with self.assertRaisesRegex(m.RollbackError, "SNAPSHOT_REPLAY_CORRUPT"):
            self.run_once()

    def test_source_changed_after_copy_prevents_promotion(self):
        raw = m._copy_code
        def mutate(source, dest, manifest):
            raw(source, dest, manifest)
            (source / "scripts/service_supervisor.py").write_text("CHANGED ASYNC")
        with patch.object(m, "_copy_code", side_effect=mutate):
            with self.assertRaisesRegex(m.RollbackError, "SOURCE_CHANGED_DURING_SNAPSHOT"):
                self.run_once()
        self.assertEqual(len(list((self.root / "data/runtime-backups").glob("verified-code-*"))), 0)

    def test_reject_missing_bootstrap_code_contract(self):
        (self.root / "scripts/service_supervisor.py").unlink()
        with self.assertRaisesRegex(m.RollbackError, "CODE_CONTRACT_INCOMPLETE"):
            self.run_once()


if __name__ == "__main__":
    unittest.main()
