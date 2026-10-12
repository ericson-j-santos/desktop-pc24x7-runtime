"""Process-backed negative controls, isolated from real Desktop supervisor."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import desktop_orchestrator_service_cycle as cycle
from scripts import desktop_orchestrator_cutover_model as model


class IsolatedServiceCycleTests(unittest.TestCase):
    def invoke(self, scenario):
        return cycle.rehearse(scenario, correlation_id="isolated-test-transaction-20261012")

    def test_positive_real_process_cutover_and_replay(self):
        result = self.invoke("success")
        self.assertEqual(result["result"], "ISOLATED_PROCESS_SWITCH_AND_REPLAY_VERIFIED")
        self.assertTrue(result["old_process_verified"])
        self.assertTrue(result["target_process_verified"])
        self.assertTrue(result["replay_verified"])
        self.assertFalse(result["old_process_recovered"])
        self.assertTrue(result["all_owned_processes_terminated"])
        self.assertFalse(result["live_supervisor_restarted"])
        self.assertFalse(result["service_rollback_verified"])
        self.assertFalse(result["recovery_allowed"])

    def test_early_exit_of_new_process_restores_old_ready(self):
        result = self.invoke("startup_exit")
        self.assertEqual(result["result"], "ISOLATED_PROCESS_ROLLBACK_VERIFIED")
        self.assertTrue(result["old_process_recovered"])
        self.assertFalse(result["target_process_verified"])
        self.assertTrue(result["all_owned_processes_terminated"])

    def test_timeout_restores_old_without_leaving_hanging_process(self):
        result = self.invoke("readiness_timeout")
        self.assertEqual(result["result"], "ISOLATED_PROCESS_ROLLBACK_VERIFIED")
        self.assertTrue(result["old_process_recovered"])
        self.assertTrue(result["all_owned_processes_terminated"])

    def test_crash_after_health_restores_old(self):
        result = self.invoke("crash_after_health")
        self.assertEqual(result["result"], "ISOLATED_PROCESS_ROLLBACK_VERIFIED")
        self.assertTrue(result["old_process_recovered"])

    def test_stale_http_identity_is_not_a_success(self):
        result = self.invoke("wrong_process_identity")
        self.assertEqual(result["result"], "ISOLATED_PROCESS_ROLLBACK_VERIFIED")
        self.assertTrue(result["old_process_recovered"])

    def test_failure_after_process_is_healthy_restores_old(self):
        result = self.invoke("postcondition_failure")
        self.assertEqual(result["result"], "ISOLATED_PROCESS_ROLLBACK_VERIFIED")
        self.assertTrue(result["old_process_recovered"])
        self.assertTrue(result["target_process_verified"])

    def test_malformed_correlation_blocks_before_subprocess(self):
        with patch.object(cycle.subprocess, "Popen", side_effect=AssertionError("MUST NOT START")):
            with self.assertRaisesRegex(cycle.ServiceCycleError, "CORRELATION_INVALID"):
                cycle.rehearse("success", correlation_id="../not-allowed")

    def test_unrecognized_scenario_blocks_before_subprocess(self):
        with patch.object(cycle.subprocess, "Popen", side_effect=AssertionError("MUST NOT START")):
            with self.assertRaisesRegex(cycle.ServiceCycleError, "SCENARIO_NOT_ALLOWED"):
                cycle.rehearse("modify-service", correlation_id="valid-correlation")

    def test_non_allowlisted_http_path_fails_closed(self):
        with self.assertRaisesRegex(cycle.ServiceCycleError, "PROBE_PATH_NOT_ALLOWED"):
            cycle._readback(8787, "/v1/status")

    def test_secret_environment_not_forwarded_to_any_child(self):
        with patch.dict(cycle.os.environ, {
            "GITHUB_TOKEN": "never-expose", "AWS_SECRET_ACCESS_KEY": "never-expose",
            "PATH": "fixture-only"
        }, clear=True):
            child_env = cycle._safe_env()
        self.assertEqual(child_env, {"PATH": "fixture-only"})
        self.assertNotIn("never-expose", json.dumps(child_env))

    def test_cli_rejects_non_dedicated_windows_runner_without_spawning(self):
        with patch.object(cycle, "rehearse", side_effect=AssertionError("MUST NOT REHEARSE")):
            with patch.dict(cycle.os.environ, {
                "RUNNER_NAME": "other-runner", "GITHUB_REPOSITORY": cycle.REPO,
                "GITHUB_SHA": "a" * 40, "GITHUB_ACTIONS": "true"
            }, clear=True):
                from contextlib import redirect_stdout
                import io
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cycle.main(["--confirm", cycle.CONFIRM, "--scenario", "success"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["result"], "ISOLATED_PROCESS_CYCLE_BLOCKED")

    def test_bad_source_file_rejected_before_owned_child_spawn(self):
        with tempfile.TemporaryDirectory(prefix="isolated-cycle-bad-script-") as temp:
            path = Path(temp) / "other-script.py"
            path.write_text("print('bad')", encoding="utf-8")
            child = cycle.ShadowChild(script=path, runtime_sha=model.OLD_SHA)
            with patch.object(cycle.subprocess, "Popen", side_effect=AssertionError("MUST NOT START")):
                with self.assertRaisesRegex(cycle.ServiceCycleError, "CHILD_START_CONTRACT_INVALID"):
                    child.start()

    def test_owned_child_can_only_be_stopped_after_launch(self):
        child = cycle.ShadowChild(script=Path("cycle-server.py"), runtime_sha=model.OLD_SHA)
        child.stop()
        self.assertTrue(child.stopped)


if __name__ == "__main__":
    unittest.main()
