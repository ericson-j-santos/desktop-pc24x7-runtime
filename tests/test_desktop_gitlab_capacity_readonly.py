"""Contratos positivos/negativos do inventario somente leitura (sem host)."""
from __future__ import annotations

import importlib.util
import ast
import json
import math
import pathlib
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "desktop_gitlab_capacity_readonly.py"
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-gitlab-capacity-readonly.yml"
SPEC = importlib.util.spec_from_file_location("desktop_gitlab_capacity_readonly", SOURCE)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)
SHA = "a" * 40
CORRELATION = "gitlab-capacity-40994086914-1"


def fixture(**overrides):
    args = {
        "source_sha": SHA,
        "correlation_id": CORRELATION,
        "hostname": lambda: "DESKTOP-PDQK954",
        "system": lambda: "Windows",
        "cpu": lambda _: 24.3,
        "memory": lambda: (64 * module.GIB, 31 * module.GIB),
        "disk": lambda: (2 * 1024 * module.GIB, 700 * module.GIB),
        "cpus": lambda: 20,
        "clock": lambda: datetime(2026, 10, 30, 2, 50, tzinfo=timezone.utc),
    }
    args.update(overrides)
    return module.collect(**args)


class CapacityProbeTests(unittest.TestCase):
    def test_positive_sample_remains_not_authorized_for_runner(self):
        result = fixture()
        self.assertTrue(result["capacity_sample_complete"])
        self.assertEqual(result["host"], "DESKTOP-PDQK954")
        self.assertEqual(result["source_sha_claim"], SHA)
        self.assertTrue(result["source_sha_must_be_validated_by_gateway"])
        self.assertEqual(result["memory_available_gib"], 31)
        self.assertEqual(result["disk_free_gib"], 700)
        self.assertEqual(result["cpu_usage_percent"], 24.3)
        self.assertEqual(result["logical_cpus"], 20)
        self.assertFalse(result["ready_for_gitlab_runner"])
        self.assertFalse(result["configuration_changed"])
        self.assertFalse(result["secrets_accessed"])
        self.assertNotIn("ip", result)
        self.assertNotIn("username", result)
        self.assertNotIn("processes", result)
        self.assertNotIn("password", json.dumps(result).lower())

    def test_unauthorized_host_rejected_before_collection(self):
        called = []
        with self.assertRaisesRegex(module.CapacityError, "host_or_os_rejected"):
            fixture(hostname=lambda: "NOTERI", cpu=lambda _: called.append("bad"))
        self.assertEqual(called, [])

    def test_linux_rejected_even_if_hostname_matches(self):
        with self.assertRaisesRegex(module.CapacityError, "host_or_os_rejected"):
            fixture(system=lambda: "Linux")

    def test_bad_sha_rejected(self):
        for value in ("main", "A" * 40, "b" * 39, "b" * 41, "$(git status)"):
            with self.subTest(sha=value), self.assertRaisesRegex(module.CapacityError, "source_sha_invalid"):
                fixture(source_sha=value)

    def test_replay_or_arbitrary_correlation_rejected(self):
        for value in ("gitlab-capacity-40994086914-2", "arbitrary", "gitlab-capacity-1-1", "gitlab-capacity-40994086914-1\nTOKEN"):
            with self.subTest(correlation=value), self.assertRaisesRegex(module.CapacityError, "correlation_invalid"):
                fixture(correlation_id=value)

    def test_missing_memory_does_not_pass(self):
        r = fixture(memory=lambda: None)
        self.assertFalse(r["capacity_sample_complete"])
        self.assertIsNone(r["memory_available_gib"])
        self.assertFalse(r["ready_for_gitlab_runner"])

    def test_corrupt_disk_does_not_pass(self):
        r = fixture(disk=lambda: (100, 101))
        self.assertFalse(r["capacity_sample_complete"])
        self.assertIsNone(r["disk_free_gib"])

    def test_missing_or_bad_cpu_does_not_pass(self):
        for value in (None, -1.0, 101.0, float("nan"), float("inf")):
            with self.subTest(cpu=value):
                r = fixture(cpu=lambda _: value)
                self.assertFalse(r["capacity_sample_complete"])
                self.assertFalse(r["ready_for_gitlab_runner"])

    def test_cpu_samples_require_two_valid_monotonic_ticks(self):
        with patch.object(module, "time"):
            values = iter([(100, 60), (200, 85)])
            delays = []
            percent = module.sample_cpu_percent(.5, reader=lambda: next(values), sleeper=delays.append)
        self.assertEqual(percent, 75.0)
        self.assertEqual(delays, [0.5])
        invalid = [[(100, 90), (100, 90)], [(100, 90), (120, 121)], [(100, 40), (90, 41)]]
        for pair in invalid:
            with self.subTest(pair=pair):
                steps = iter(pair)
                self.assertIsNone(module.sample_cpu_percent(.5, reader=lambda: next(steps), sleeper=lambda _: None))

    def test_window_and_naive_timestamp_fail_closed(self):
        for value in (0.0, 0.1, 5.1, float("nan"), float("inf")):
            with self.subTest(window=value), self.assertRaisesRegex(module.CapacityError, "sample_window_invalid"):
                fixture(sample_seconds=value)
        with self.assertRaisesRegex(module.CapacityError, "timestamp_not_utc"):
            fixture(clock=lambda: datetime(2026, 10, 30, 3, 0))

    def test_repeat_read_produces_identical_result_when_inputs_unchanged(self):
        self.assertEqual(fixture(), fixture())

    def test_no_shell_network_environment_or_secret_harvesting(self):
        text = SOURCE.read_text(encoding="utf-8")
        code = ast.parse(text)
        imported = [x.names[0].name for x in ast.walk(code) if isinstance(x, ast.Import)]
        self.assertTrue(set(imported).isdisjoint({"subprocess", "requests", "psutil", "sqlite3"}))
        for forbidden in ("os.system(", "shell=True", "requests.", "socket.connect", "os.environ", "getenv(", "docker run", "docker inspect"):
            self.assertNotIn(forbidden, text.lower())


class WorkflowStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.data = yaml.load(cls.text, Loader=yaml.BaseLoader)

    def test_only_manual_trigger_no_workflow_data_upload(self):
        data = self.data
        self.assertEqual(set(data["on"]), {"workflow_dispatch"})
        self.assertEqual(set(data["jobs"]), {"capacity", "queue_watchdog"})
        self.assertNotIn("upload-artifact", self.text)
        self.assertNotIn("docker run", self.text.lower())
        self.assertNotIn("gitlab-runner register", self.text.lower())
        self.assertNotIn("pull_request:", self.text)
        self.assertNotIn("schedule:", self.text)
        self.assertNotIn("push:", self.text)

    def test_exact_runner_and_identity_gates(self):
        d = self.data
        runs_on = d["jobs"]["capacity"]["runs-on"]
        self.assertEqual(runs_on, ["self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime", "runtime-dev", "desktop-pdqk954"])
        for marker in (
            "context.actor !== 'ericson-j-santos'", "context.ref !== 'refs/heads/main'",
            "context.eventName !== 'workflow_dispatch'", "context.sha !== expected",
            "matches[0].runner_id !== 2", "process.env.RUNNER_NAME !== 'DESKTOP-PDQK954-runtime'",
            "rules.commit.sha !== rulesExpected", "main.commit.sha !== expected",
        ):
            self.assertIn(marker, self.text)

    def test_session_gateway_read_only_and_negative_controls(self):
        for marker in (
            "--require-runner-version-preflight", "SESSION_LAUNCH_OK", "state_validated",
            "--risk 1", "--expected-head $env:EXPECTED_HEAD",
            "--session-id $env:SESSION_ID", "scripts/desktop_gitlab_capacity_readonly.py",
            "ready_for_gitlab_runner -ne $false", "CAPACITY_SAMPLE_READBACK_INVALID",
            "CAPACITY_MEASURED_NOT_RUNNER_APPROVED", "configuration_changed -ne $false",
            "CAPACITY_PHYSICAL_PICKUP_TIMEOUT_300S", "CAPACITY_WRONG_OR_UNATTRIBUTED_RUNNER",
        ):
            self.assertIn(marker, self.text)
        self.assertEqual(self.data["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(self.data["jobs"]["queue_watchdog"]["permissions"], {"actions": "write", "contents": "read"})

    def test_source_action_references_are_pinned(self):
        for line in self.text.splitlines():
            if "uses:" in line:
                action = line.split("uses:", 1)[1].strip()
                self.assertRegex(action, r"^[^\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
