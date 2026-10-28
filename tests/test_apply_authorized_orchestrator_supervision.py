"""Specific approval gate before any local state or credential access."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "apply_authorized_orchestrator_supervision.py"
spec = importlib.util.spec_from_file_location("supervision_authorized", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ApprovalGateTests(unittest.TestCase):
    def test_missing_or_wrong_approval_blocks_before_subprocess(self):
        for value in ("", "wrong", module.DIGEST[:-1]):
            out = io.StringIO()
            with self.subTest(value=value), patch.dict(os.environ, {"EXACT_PLAN_APPROVAL": value}, clear=True), \
                 patch.object(module.subprocess, "run") as run, redirect_stdout(out):
                self.assertEqual(module.main(), 2)
                run.assert_not_called()
            receipt = json.loads(out.getvalue())
            self.assertFalse(receipt["ok"])
            self.assertFalse(receipt["apply_invoked"])
            self.assertEqual(receipt["state"], "administrative_approval_required")
    def test_closed_identity_and_digest(self):
        self.assertEqual(module.SOURCE_SHA, "a9c3fe785a2cb1229f3629127e71f8039c3216f2")
        self.assertEqual(module.DIGEST, "d291fb00d84c35bc7e7392b5909d434bf7b0f8d817bd76e43a688bb2d0d937ff")
        self.assertEqual(module.CORRELATION, "orchestrator-dev-supervision-review")
        self.assertIn("/environment/dev/", module.SCOPE)
        self.assertNotIn("shell=True", SCRIPT.read_text())
if __name__ == "__main__":
    unittest.main()
