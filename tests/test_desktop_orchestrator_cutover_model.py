"""Strict fail-closed transaction model: all filesystem effects stay in TEMP."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import desktop_orchestrator_cutover_model as m


def accepted(_sha):
    return {"ready": True, "runtime_sha": m.TARGET_SHA, "worker_instance_changed": True}


class CutoverModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cutover-transaction-test-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        (self.home / m.SIMULATION_MARKER).write_text(m.SIMULATION_VALUE, encoding="utf-8")
        self._release("active", m.OLD_SHA, "old version\n")
        self._release("candidate", m.TARGET_SHA, "candidate version\n")
        self.correlation = "cutover-fixture-20261012-v1"

    def _release(self, name: str, sha: str, code: str):
        folder = self.home / name
        folder.mkdir()
        (folder / "runtime-version.json").write_text(
            json.dumps({"schema_version": 1, "source_sha": sha}), encoding="utf-8"
        )
        (folder / "code-proof.txt").write_text(code, encoding="utf-8")

    def run_cutover(self, fail=None, health=accepted, correlation=None):
        return m.simulate_transaction(
            self.home, correlation_id=correlation or self.correlation,
            health=health, inject_at=fail,
        )

    def assert_rollback_good(self):
        self.assertEqual(m._read_sha(self.home / "active"), m.OLD_SHA)
        self.assertEqual(m._read_sha(self.home / "candidate"), m.TARGET_SHA)
        self.assertFalse((self.home / "previous").exists())
        self.assertFalse((self.home / ".transaction.lock").exists())

    def test_positive_simulated_swap_and_replay_is_idempotent(self):
        result = self.run_cutover()
        self.assertEqual(result["result"], "SIMULATED_SWITCH_COMMITTED")
        self.assertTrue(result["simulated_only"])
        self.assertFalse(result["recovery_allowed"])
        self.assertFalse(result["service_restarted"])
        self.assertEqual(m._read_sha(self.home / "active"), m.TARGET_SHA)
        self.assertEqual(m._read_sha(self.home / "previous"), m.OLD_SHA)
        self.assertEqual(json.loads((self.home / m.JOURNAL).read_text())["state"], "COMMITTED")
        replay = self.run_cutover(health=lambda _: self.fail("replay health must not run"))
        self.assertTrue(replay["replayed"])
        self.assertEqual(m._read_sha(self.home / "active"), m.TARGET_SHA)
        self.assertFalse((self.home / ".transaction.lock").exists())

    def test_failure_after_old_release_move_restores_exact_old(self):
        with self.assertRaises(m.CutoverFailure) as cm:
            self.run_cutover(fail="after_old_move")
        self.assertEqual(cm.exception.code, "SIMULATED_ROLLBACK_VERIFIED")
        self.assertTrue(cm.exception.restored)
        self.assert_rollback_good()
        with self.assertRaisesRegex(m.CutoverFailure, "INCOMPLETE_TRANSACTION"):
            self.run_cutover()

    def test_failure_after_new_release_move_restores_exact_old(self):
        with self.assertRaises(m.CutoverFailure) as cm:
            self.run_cutover(fail="after_new_move")
        self.assertEqual(cm.exception.code, "SIMULATED_ROLLBACK_VERIFIED")
        self.assertTrue(cm.exception.restored)
        self.assert_rollback_good()

    def test_simulated_new_service_health_failure_uses_rollback(self):
        with self.assertRaises(m.CutoverFailure) as cm:
            self.run_cutover(health=lambda _: {"ready": False, "runtime_sha": m.TARGET_SHA})
        self.assertTrue(cm.exception.restored)
        self.assert_rollback_good()

    def test_worker_instance_must_change_or_rollback(self):
        with self.assertRaises(m.CutoverFailure) as cm:
            self.run_cutover(health=lambda _: {
                "ready": True, "runtime_sha": m.TARGET_SHA,
                "worker_instance_changed": False,
            })
        self.assertTrue(cm.exception.restored)
        self.assert_rollback_good()

    def test_unexpected_health_exception_triggers_rollback(self):
        def fail(_):
            raise RuntimeError("fake network failure")
        with self.assertRaises(m.CutoverFailure) as cm:
            self.run_cutover(health=fail)
        self.assertTrue(cm.exception.restored)
        self.assert_rollback_good()

    def test_bad_target_sha_blocks_before_any_move(self):
        (self.home / "candidate/runtime-version.json").write_text(
            json.dumps({"schema_version": 1, "source_sha": "c" * 40})
        )
        with self.assertRaisesRegex(m.CutoverFailure, "RELEASE_SHA_MISMATCH"):
            self.run_cutover()
        self.assertEqual(m._read_sha(self.home / "active"), m.OLD_SHA)
        self.assertFalse((self.home / m.JOURNAL).exists())

    def test_invalid_correlation_blocks_without_mutation(self):
        with self.assertRaisesRegex(m.CutoverFailure, "CORRELATION_INVALID"):
            self.run_cutover(correlation="../invalid")
        self.assertEqual(m._read_sha(self.home / "active"), m.OLD_SHA)

    def test_concurrent_operation_lock_fails_closed(self):
        (self.home / ".transaction.lock").write_text("occupied")
        with self.assertRaisesRegex(m.CutoverFailure, "TRANSACTION_LOCKED"):
            self.run_cutover()
        self.assertFalse((self.home / m.JOURNAL).exists())

    def test_marker_missing_or_wrong_blocks_all_moves(self):
        marker = self.home / m.SIMULATION_MARKER
        marker.unlink()
        with self.assertRaisesRegex(m.CutoverFailure, "SIMULATION_MARKER_MISSING"):
            self.run_cutover()
        marker.write_text("incorrect")
        with self.assertRaisesRegex(m.CutoverFailure, "SIMULATION_MARKER_INVALID"):
            self.run_cutover()
        self.assertEqual(m._read_sha(self.home / "active"), m.OLD_SHA)

    def test_tampered_success_journal_cannot_fake_replay(self):
        self.run_cutover()
        (self.home / "active/code-proof.txt").write_text("unauthorized changed code")
        with self.assertRaisesRegex(m.CutoverFailure, "COMMITTED_TRANSACTION_IDENTITY_MISMATCH"):
            self.run_cutover()

    def test_unexpected_lock_or_journal_cannot_auto_recover(self):
        (self.home / m.JOURNAL).write_text("not-json")
        with self.assertRaisesRegex(m.CutoverFailure, "JOURNAL_INVALID"):
            self.run_cutover()
        self.assertEqual(m._read_sha(self.home / "active"), m.OLD_SHA)

    def test_gate_missing_protection_and_risk3_are_blocking(self):
        evidence = self._evidence()
        evidence.gates["desktop_main_protected"] = False
        evidence.gates["orchestrator_main_protected"] = False
        evidence.gates["risk3_cutover_approved"] = False
        decision = m.review(evidence)
        self.assertEqual(decision["result"], "CUTOVER_GATES_BLOCKED")
        self.assertIn("desktop_main_protected", decision["missing_gates"])
        self.assertIn("risk3_cutover_approved", decision["missing_gates"])
        self.assertFalse(decision["recovery_allowed"])

    def test_wrong_host_sha_and_environment_block_even_when_gates_true(self):
        from dataclasses import replace
        evidence = self._evidence()
        for altered in (
            replace(evidence, host="Noteri"),
            replace(evidence, environment="production"),
            replace(evidence, target_sha="f" * 40),
            replace(evidence, old_sha="f" * 40),
            replace(evidence, target_repo="other/repo"),
            replace(evidence, approval_correlation_id="../bad"),
        ):
            with self.subTest(altered=altered):
                self.assertEqual(m.review(altered)["result"], "CUTOVER_IDENTITY_BLOCKED")

    def test_even_reviewable_gate_snapshot_never_executes_physical_cutover(self):
        result = m.review(self._evidence())
        self.assertEqual(result["result"], "CUTOVER_REVIEWABLE")
        self.assertEqual(result["missing_gates"], [])
        self.assertFalse(result["service_restarted"])
        self.assertFalse(result["recovery_allowed"])

    def test_real_installed_root_is_not_a_simulation_target(self):
        with patch.object(m.tempfile, "gettempdir", return_value="/tmp/transaction-only"):
            with self.assertRaisesRegex(m.CutoverFailure, "SIMULATION_SCOPE_FORBIDDEN"):
                m.simulate_transaction(m.Path("/home/live/orchestrator"),
                                       correlation_id=self.correlation, health=accepted)

    @staticmethod
    def _evidence():
        return m.CutoverEvidence(
            host=m.HOST, environment="dev", old_sha=m.OLD_SHA,
            target_repo=m.TARGET_REPO, target_sha=m.TARGET_SHA,
            approval_correlation_id="approval-cutover-20261012",
            gates={name: True for name in m.REQUIRED_GATES},
        )


if __name__ == "__main__":
    unittest.main()
