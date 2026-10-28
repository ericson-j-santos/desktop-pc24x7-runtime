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
        self.assertEqual(module.SOURCE_SHA, "e0c40bccf0d99858a21beab0d62d0f143e969608")
        self.assertEqual(module.DIGEST, "e74b89a5c9ca49ca2b6695d13332e81873dd363e770a9a65894e7a76e5e63396")
        self.assertEqual(module.CORRELATION, "orchestrator-dev-supervision-review")
        self.assertIn("/environment/dev/", module.SCOPE)
        self.assertNotIn("shell=True", SCRIPT.read_text())
if __name__ == "__main__":
    unittest.main()
