from __future__ import annotations
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("authorized_apply_test", Path(__file__).resolve().parents[1] / "scripts/orchestrator_registration_apply_authorized.py")
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def plan():
    return {"source_sha": m.SOURCE_SHA, "plan_sha256": m.DIGEST,
            "correlation_id": m.CORRELATION, "ok": True,
            "profile": {"host": "DESKTOP-PDQK954",
                        "repository": "ericson-j-santos/reqsys-engineering-orchestrator",
                        "runner_name": "DESKTOP-PDQK954-orchestrator-dev"},
            "package": {"version": "2.338.2"},
            "listener_start_planned": False, "watchdog_change_planned": False,
            "windows_task_change_planned": False, "runtime_runner_change_planned": False,
            "additional_cost_authorized_brl": 0}


class ApprovalBindingTests(unittest.TestCase):
    def test_exact_plan_accepted(self):
        m.require_approved_plan(plan())

    def test_source_digest_environment_and_effect_changes_rejected(self):
        for key, value in (("source_sha", "b" * 40), ("plan_sha256", "b" * 64),
                           ("listener_start_planned", True),
                           ("windows_task_change_planned", True),
                           ("additional_cost_authorized_brl", 1)):
            candidate = deepcopy(plan())
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.require_approved_plan(candidate)
        candidate = plan()
        candidate["profile"]["repository"] = "another/repository"
        with self.assertRaises(ValueError):
            m.require_approved_plan(candidate)

    def test_command_uses_exact_approved_registration_contract(self):
        args = m.application_args()
        self.assertEqual(args[args.index("--expected-plan-sha256") + 1], m.DIGEST)
        self.assertEqual(args[args.index("--source-sha") + 1], m.SOURCE_SHA)
        self.assertEqual(args[args.index("--correlation-id") + 1], m.CORRELATION)
        self.assertIn("--apply", args)
        self.assertNotIn("--enable", args)
        self.assertNotIn("--token", args)


if __name__ == "__main__":
    unittest.main()
