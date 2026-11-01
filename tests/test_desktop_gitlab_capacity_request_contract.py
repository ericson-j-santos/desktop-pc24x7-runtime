"""Stdlib structural safety contracts; full YAML/Windows CI remains required."""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / ".github/workflows/desktop-gitlab-capacity-readonly.yml"

def contract(text):
    assert "  issues:\n    types: [opened]\n" in text
    assert "  workflow_dispatch:" in text
    assert not any(marker in text for marker in ("  push:", "  schedule:", "  pull_request:", "upload-artifact", "contents: write", "issues: write"))
    assert text.count("actions: write") == 1
    assert text.index("actions: write") > text.index("  queue_watchdog:")
    assert "permissions:\n  contents: read\n  actions: read\n" in text
    assert text.count("    needs: [admission]") == 2
    assert text.count("!cancelled() &&") == 2 and "always()" not in text
    assert text.count("needs.admission.outputs.admitted == 'true'") == 2
    assert text.count("needs.admission.result == 'success'") == 2
    assert "    types: [opened]" in text
    assert "runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev, desktop-pdqk954]" in text
    assert "matches[0].runner_id !== 2" in text
    assert "const deadline = anchor + 300000;" in text
    assert "cancel-in-progress: false" in text
    assert "\nconcurrency:" not in text.split("\njobs:", 1)[0]
    capacity = text.split("  capacity:\n", 1)[1].split("  queue_watchdog:", 1)[0]
    assert "    concurrency:\n      group: desktop-gitlab-capacity-readonly\n      cancel-in-progress: false" in capacity
    claim = text.split("      - name: Consume issue request", 1)[1].split("      - name: Measure native", 1)[0]
    measure = text.split("      - name: Measure native", 1)[1].split("  queue_watchdog:", 1)[0]
    assert "--risk 2" in claim and "scripts/desktop_gitlab_capacity_claim.py" in claim
    assert "audit_state_changed -ne $true" in claim
    assert "--risk 1" in measure and "--risk 2" not in measure
    assert "steps.claim.outputs.claimed == 'true'" in measure
    assert "scripts/desktop_gitlab_capacity_admission.py --verify-only" in measure
    assert measure.index("--verify-only") < measure.index("scripts/desktop_gitlab_capacity_readonly.py")
    assert "configuration_changed -ne $false" in measure
    for line in text.splitlines():
        if "uses:" in line:
            assert re.fullmatch(r"[^\s]+@[0-9a-f]{40}", line.split("uses:", 1)[1].strip())

class RequestWorkflowTests(unittest.TestCase):
    def test_current_contract(self):
        contract(FILE.read_text())

    def test_known_gate_mutations_are_detected(self):
        text = FILE.read_text()
        for before, after in [
            ("types: [opened]", "types: [opened, edited]"),
            ("needs: [admission]", "needs: []"),
            ("!cancelled()", "always()"),
            ("needs.admission.result == 'success'", "true"),
            ("    concurrency:", "    concurrency_disabled:"),
            ("matches[0].runner_id !== 2", "matches[0].runner_id !== 3"),
            ("anchor + 300000", "anchor + 999999"),
            ("cancel-in-progress: false", "cancel-in-progress: true"),
            ("--risk 2", "--risk 1"),
            ("--verify-only", "--skip-check"),
            ("audit_state_changed -ne $true", "audit_state_changed -ne $false"),
            ("steps.claim.outputs.claimed == 'true'", "true"),
        ]:
            with self.subTest(before=before), self.assertRaises(AssertionError):
                contract(text.replace(before, after))

    def test_source_syntax_and_no_execution_of_request_content(self):
        for name in ("desktop_gitlab_capacity_admission.py", "desktop_gitlab_capacity_claim.py"):
            source = (ROOT / "scripts" / name).read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ("eval", "exec", "compile"))
            self.assertNotIn("subprocess", source)
            self.assertNotIn("os.system", source)

    def test_native_windows_gate_remains_present(self):
        native = (ROOT / "tests/test_desktop_gitlab_capacity_windows_native.py").read_text()
        self.assertIn("windows-latest", (ROOT / ".github/workflows/ci.yml").read_text())
        self.assertIn('unittest.skipUnless(os.name == "nt"', native)
        self.assertIn("with m.windows_private_root(self.root):", native)
        self.assertIn("NULL_DACL_REJECTED", native)
        self.assertIn("REPARSE_REJECTED", native)
        self.assertNotIn("self.skipTest", native)

    def test_ci_automatically_discovers_python_tests(self):
        self.assertIn("python -m pytest -ra", (ROOT / ".github/workflows/ci.yml").read_text())

if __name__ == "__main__":
    unittest.main()
