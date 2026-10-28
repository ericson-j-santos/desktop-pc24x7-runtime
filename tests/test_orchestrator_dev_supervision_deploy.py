"""Closed supervision deployment contracts; no physical mutation in unit tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import orchestrator_dev_supervision_deploy as deploy


class TaskContractTests(unittest.TestCase):
    def setUp(self):
        self.python = Path("/governed/python.exe")
        self.launcher = Path("/governed/watchdog/run.py")
        self.sid = "S-1-5-21-1234"
        self.xml = deploy.task_xml(self.python, self.launcher, self.sid)

    def test_same_identity_boot_minute_contract(self):
        result = deploy.validate_task(self.xml, self.python, self.launcher, self.sid)
        self.assertTrue(all(result.values()))
        self.assertNotIn(self.sid, json.dumps(result))

    def test_other_principal_rejected(self):
        with self.assertRaisesRegex(deploy.Blocked, "task_binding_rejected"):
            deploy.validate_task(self.xml, self.python, self.launcher, "S-1-5-21-9999")

    def test_other_paths_rejected(self):
        for python, launcher in ((Path("/other/python"), self.launcher),
                                 (self.python, Path("/other/run.py"))):
            with self.assertRaises(deploy.Blocked):
                deploy.validate_task(self.xml, python, launcher, self.sid)

    def test_task_policy_changes_rejected(self):
        raw = self.xml.decode("utf-16")
        for old, new in (("S4U", "Password"), ("LeastPrivilege", "HighestAvailable"),
                         ("PT1M", "PT5M"), ("IgnoreNew", "Parallel"),
                         ("DesktopPc24x7RuntimeWatchdog", "OtherTask")):
            with self.subTest(old=old), self.assertRaises(deploy.Blocked):
                deploy.validate_task(raw.replace(old, new).encode("utf-16"),
                                     self.python, self.launcher, self.sid)

    def test_malformed_or_large_xml_rejected(self):
        with self.assertRaises(Exception):
            deploy.validate_task(b"<invalid", self.python, self.launcher, self.sid)
        with self.assertRaisesRegex(deploy.Blocked, "task_xml_too_large"):
            deploy.validate_task(b"x" * 262145, self.python, self.launcher, self.sid)

    def test_sid_argument_cannot_inject_xml(self):
        with self.assertRaisesRegex(deploy.Blocked, "task_sid_invalid"):
            deploy.task_xml(self.python, self.launcher, "bad<xml>")


class ApplySafetyTests(unittest.TestCase):
    def test_confirmation_checked_before_source_or_host(self):
        with patch.object(deploy, "source_guard") as guard:
            with self.assertRaisesRegex(deploy.Blocked, "confirmation_invalid"):
                deploy.apply("a" * 40, "safe-correlation", "b" * 64, "no")
            guard.assert_not_called()

    def test_digest_checked_before_source_or_host(self):
        with patch.object(deploy, "source_guard") as guard:
            with self.assertRaisesRegex(deploy.Blocked, "plan_digest_invalid"):
                deploy.apply("a" * 40, "safe-correlation", "", deploy.CONFIRM)
            guard.assert_not_called()

    def test_changed_plan_never_pauses_scanner(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(deploy, "source_guard"), \
                 patch.object(deploy, "receipt_path", return_value=Path(temp) / "receipt.json"), \
                 patch.object(deploy, "build_plan", return_value={"plan_sha256": "c" * 64}), \
                 patch.object(deploy, "pause_scanner") as pause:
                with self.assertRaisesRegex(deploy.Blocked, "activation_plan_changed"):
                    deploy.apply("a" * 40, "safe-correlation", "b" * 64, deploy.CONFIRM)
                pause.assert_not_called()

    def test_pause_uncertain_still_restores_and_persists_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            with patch.object(deploy, "source_guard"), \
                 patch.object(deploy, "receipt_path", return_value=path), \
                 patch.object(deploy, "build_plan", return_value={"plan_sha256": "b" * 64}), \
                 patch.object(deploy.bootstrap, "local_git_owner_token", return_value="opaque-test"), \
                 patch.object(deploy, "scanner_guard"), \
                 patch.object(deploy, "workflow_state", return_value={"state": "active"}), \
                 patch.object(deploy, "pause_scanner", side_effect=deploy.Blocked("scanner_pause_unconfirmed")), \
                 patch.object(deploy, "restore_scanner") as restore:
                result = deploy.apply("a" * 40, "safe-correlation", "b" * 64, deploy.CONFIRM)
            restore.assert_called_once()
            self.assertFalse(result["ok"])
            self.assertTrue(result["scanner_workflow_restored"])
            self.assertEqual(json.loads(path.read_text())["state"], "scanner_pause_unconfirmed")
            self.assertNotIn("opaque-test", path.read_text())

    def test_failure_to_restore_is_blocking_and_preserves_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            with patch.object(deploy, "source_guard"), \
                 patch.object(deploy, "receipt_path", return_value=path), \
                 patch.object(deploy, "build_plan", return_value={"plan_sha256": "b" * 64}), \
                 patch.object(deploy.bootstrap, "local_git_owner_token", return_value="opaque-test"), \
                 patch.object(deploy, "scanner_guard"), \
                 patch.object(deploy, "workflow_state", return_value={"state": "active"}), \
                 patch.object(deploy, "pause_scanner", side_effect=deploy.Blocked("scanner_pause_unconfirmed")), \
                 patch.object(deploy, "restore_scanner", side_effect=RuntimeError("do not log token")):
                result = deploy.apply("a" * 40, "safe-correlation", "b" * 64, deploy.CONFIRM)
            self.assertEqual(result["state"], "scanner_restore_unconfirmed")
            self.assertFalse(result["ok"])
            self.assertNotIn("do not log token", path.read_text())

    def test_partial_receipt_never_reapplies(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "receipt.json"
            path.write_text(json.dumps({"ok": False, "source_sha": "a" * 40, "plan_sha256": "b" * 64}))
            with patch.object(deploy, "source_guard"), \
                 patch.object(deploy, "receipt_path", return_value=path), \
                 patch.object(deploy, "build_plan") as plan:
                with self.assertRaisesRegex(deploy.Blocked, "activation_receipt_conflict"):
                    deploy.apply("a" * 40, "safe-correlation", "b" * 64, deploy.CONFIRM)
                plan.assert_not_called()

    def test_create_only_never_overwrites_existing_task(self):
        with patch.object(deploy, "query_task", return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(deploy.subprocess, "run") as run:
            with self.assertRaisesRegex(deploy.Blocked, "task_appeared_before_create"):
                deploy.create_task({})
            run.assert_not_called()

    def test_digest_is_order_independent_and_sensitive(self):
        self.assertEqual(deploy.digest({"a": 1, "b": 2}), deploy.digest({"b": 2, "a": 1}))
        self.assertNotEqual(deploy.digest({"a": 1}), deploy.digest({"a": 2}))

    def test_error_output_drops_untyped_sensitive_detail(self):
        self.assertEqual(deploy.safe_state(RuntimeError("secret-token")), "supervision_operation_blocked")

    def test_no_shell_or_task_force_contract(self):
        source = Path(deploy.__file__).read_text()
        self.assertNotIn('shell=True', source)
        self.assertNotIn('"/F"', source)
        self.assertNotIn('"/Delete"', source)
        self.assertNotIn('"/RU"', source)
        self.assertNotIn('"/RP"', source)
        self.assertNotIn('auth login', source)


if __name__ == "__main__":
    unittest.main()
