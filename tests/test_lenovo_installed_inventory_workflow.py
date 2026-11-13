from __future__ import annotations

import unittest
from pathlib import Path

import yaml

WORKFLOW = (Path(__file__).resolve().parents[1] / ".github" / "workflows"
            / "lenovo-installed-inventory-readonly.yml")


class LenovoInventoryWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.source, Loader=yaml.BaseLoader)
        cls.job = cls.workflow["jobs"]["inventory"]

    def test_only_manual_dispatch_and_fixed_inputs(self):
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), {"expected_source_sha", "confirmation"})
        self.assertEqual(inputs["confirmation"]["options"], ["READ_ONLY_LENOVO_INVENTORY"])

    def test_owner_main_first_attempt_exact_sha_guard(self):
        guard = self.job["if"]
        for required in ("github.actor == 'ericson-j-santos'",
                         "github.triggering_actor == 'ericson-j-santos'",
                         "github.ref == 'refs/heads/main'",
                         "vars.REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA == github.sha"):
            self.assertIn(required, guard)
        admit = self.job["steps"][0]["with"]["script"]
        for required in ("GITHUB_RUN_ATTEMPT", "context.sha", "main.commit.sha",
                         "LENOVO_INVENTORY_EXACT_CI_REQUIRED",
                         "LENOVO_INVENTORY_CI_GATES_REQUIRED"):
            self.assertIn(required, admit)

    def test_runner_is_exact_lenovo_and_no_fallback(self):
        self.assertEqual(self.job["runs-on"],
                         ["self-hosted", "Windows", "X64", "pc24x7",
                          "desktop-runtime", "runtime-dev", "desktop-rp23ogs"])
        self.assertEqual(self.job["environment"], "DEV")
        self.assertEqual(set(self.workflow["permissions"]),
                         {"contents", "actions"})
        self.assertEqual(set(self.job["env"]), {"DEPLOYMENT_ENV", "CORRELATION_ID"})

    def test_only_immutable_actions(self):
        refs = [step["uses"] for step in self.job["steps"] if "uses" in step]
        self.assertEqual(len(refs), 3)
        for ref in refs:
            self.assertRegex(ref, r"^actions/(github-script|checkout)@[0-9a-f]{40}$")

    def test_gateway_risk1_and_no_mutating_commands(self):
        scripts = [step["run"] for step in self.job["steps"] if "run" in step]
        joined = "\n".join(scripts)
        self.assertIn("'--risk','1'", joined)
        self.assertIn("lenovo_control_plane_installed_inventory.py", joined)
        self.assertNotIn("upgrade_desktop_free_control_plane.py", joined)
        self.assertNotIn("subprocess.run(command,shell=True", joined)
        self.assertNotIn("actions/upload-artifact", self.source)
        self.assertIn("'--expected-head',sha", joined)
        self.assertIn("capture_output=True", joined)
        self.assertIn("mutation_performed", joined)

    def test_readonly_receipt_has_sha_digest_controls(self):
        final = self.job["steps"][-1]["run"]
        for key in ("expected_installed_sha", "metadata_sha256", "expected_watchdog_sha256",
                    "expected_uac_sha256", "expected_launcher_sha256"):
            self.assertIn(key, final)
        self.assertIn("payload.get('upgrade_authorized') is not False", final)
        self.assertIn("payload.get('double_read_verified') is not True", final)
        self.assertIn("type(payload.get('upgrade_profile_root_aligned')) is not bool", final)
        self.assertIn("payload.get('runner_health_proven') is not False", final)
        self.assertIn("payload.get('github_pickup_proven') is not False", final)
        self.assertIn("'upgrade_profile_root_aligned','double_read_verified'", final)
        self.assertIn("if process.returncode!=0:", final)

    def test_upgrade_profile_mismatch_is_visible_not_a_claim_of_readiness(self):
        script = self.job["steps"][-1]["run"]
        self.assertIn("upgrade_profile_root_aligned", script)
        self.assertIn("payload.get('upgrade_authorized') is not False", script)
        self.assertIn("payload.get('runner_health_proven') is not False", script)
        self.assertNotIn("upgrade_desktop_free_control_plane.py", script)

    @staticmethod
    def _simulated_gateway_receipt(**changes):
        import json
        sha = "a" * 40
        payload = {
            "contract": "lenovo-installed-inventory-readonly-v1",
            "result": "INSTALLED_INVENTORY_READ_ONLY",
            "host": "DESKTOP-RP23OGS",
            "runner_name": "DESKTOP-RP23OGS-runtime",
            "double_read_verified": True,
            "upgrade_profile_root_aligned": False,
            "runner_health_proven": False,
            "github_pickup_proven": False,
            "mutation_performed": False,
            "upgrade_authorized": False,
            "expected_installed_sha": sha,
            "metadata_sha256": "b" * 64,
            "expected_watchdog_sha256": "c" * 64,
            "expected_uac_sha256": "d" * 64,
            "expected_launcher_sha256": "e" * 64,
        }
        gateway = {
            "action": "run", "risk": 1, "result": "ok",
            "cwd": "/isolated/target",
            "gateway_exit_code": 0, "command_exit_code": 0,
            "state_changed": False,
            "session_id": "expected-session",
            "correlation_id": "lenovo-control-plane-pickup-123-1",
            "before": {"head": sha}, "after": {"head": sha},
            "stdout": json.dumps(payload),
        }
        gateway.update(changes)
        return gateway

    def _run_receipt(self, gateway):
        import contextlib
        import io
        import json
        import os
        from types import SimpleNamespace
        from unittest.mock import patch
        variables = {
            "GITHUB_WORKSPACE": "/isolated/repo",
            "TARGET_PATH": "/isolated/target",
            "ANCHOR_SHA": "a" * 40,
            "GITHUB_SHA": "a" * 40,
            "SESSION_ID": "expected-session",
            "CORRELATION_ID": "lenovo-control-plane-pickup-123-1",
        }
        output = io.StringIO()
        process = SimpleNamespace(returncode=0, stdout=json.dumps(gateway))
        with patch.dict(os.environ, variables):
            with patch("subprocess.run", return_value=process):
                with contextlib.redirect_stdout(output):
                    exec(self.job["steps"][-1]["run"], {"__name__": "__main__"})
        return json.loads(output.getvalue().strip())

    def test_gateway_receipt_positive_with_exact_session_and_sha(self):
        report = self._run_receipt(self._simulated_gateway_receipt())
        self.assertEqual(report["result"], "INSTALLED_INVENTORY_READ_ONLY")
        self.assertFalse(report["upgrade_authorized"])
        self.assertFalse(report["upgrade_profile_root_aligned"])

    def test_gateway_receipt_negative_wrong_session_correlation_and_head(self):
        changes = (
            {"session_id": "different-session"},
            {"correlation_id": "different-correlation"},
            {"gateway_exit_code": 17},
            {"gateway_exit_code": False},
            {"command_exit_code": False},
            {"action": "inspect"},
            {"risk": 2},
            {"risk": True},
            {"cwd": "/isolated/other-repo"},
            {"cwd": None},
            {"before": {"head": "f" * 40}},
            {"after": {"head": "f" * 40}},
            {"before": None},
            {"after": None},
            {"session_id": None},
            {"correlation_id": None},
        )
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaisesRegex(
                        RuntimeError, "LENOVO_INVENTORY_RECEIPT_REJECTED"):
                    self._run_receipt(self._simulated_gateway_receipt(**change))

    def test_no_executable_dispatch_on_main_from_branch(self):
        self.assertEqual(self.workflow["concurrency"]["cancel-in-progress"], "false")
        self.assertIn("${{ github.run_id }}", self.source)
        self.assertIn("${{ steps.admit.outputs.rules_sha }}", self.source)


if __name__ == "__main__":
    unittest.main()
