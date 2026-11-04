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

    def test_claim_denial_is_classified_without_raw_output(self):
        workflow = FILE.read_text()
        claim = workflow.split("      - name: Consume issue request", 1)[1].split("      - name: Measure native", 1)[0]

        def guard(script):
            self.assertIn("$gatewayExit = $LASTEXITCODE", script)
            self.assertIn("if ($gatewayExit -ne 0 -or -not $raw)", script)
            self.assertIn("$failureClass = 'UNCLASSIFIED'", script)
            self.assertIn("if ($allowedClasses -ccontains $candidate)", script)
            self.assertIn("'SOURCE_CHANGED'", script)
            self.assertIn("'REQUEST_ALREADY_CONSUMED_OR_UNCERTAIN'", script)
            self.assertIn("Write-Output (\"AUDIT_CLAIM_FAILURE_CLASS=\" + $failureClass)", script)
            self.assertIn("throw 'AUDIT_CLAIM_BLOCKED'", script)
            self.assertNotIn("Write-Output $raw", script)
            self.assertNotIn("Write-Output $candidate", script)
            self.assertNotIn("Write-Output $gatewayReply", script)
            self.assertLess(script.index('Write-Output ("AUDIT_CLAIM_FAILURE_CLASS='), script.index("throw 'AUDIT_CLAIM_BLOCKED'"))

        guard(claim)
        for old, replacement in (
            ("-ccontains $candidate", "-contains $candidate"),
            ("throw 'AUDIT_CLAIM_BLOCKED'", "Write-Output 'CLAIM_NOT_BLOCKED'"),
            ("$failureClass = 'UNCLASSIFIED'", "$failureClass = $candidate"),
            ('Write-Output ("AUDIT_CLAIM_FAILURE_CLASS=" + $failureClass)', 'Write-Output $raw'),
        ):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                guard(claim.replace(old, replacement))

    @unittest.skipUnless(__import__("os").name == "nt", "Win32 PowerShell fixture only")
    def test_claim_denial_powershell_runtime_sanitization(self):
        # Hosted Windows fixture only; never invokes a Desktop Gateway or claim.
        import base64
        import json
        import shutil
        import subprocess

        shell = shutil.which("powershell.exe")
        self.assertIsNotNone(shell, "Windows hosted CI must provide Windows PowerShell")
        workflow = FILE.read_text()
        claim = workflow.split("      - name: Consume issue request", 1)[1].split("      - name: Measure native", 1)[0]
        fragment = claim.split("          $gatewayExit = $LASTEXITCODE\n", 1)[1].split("          $event = @($raw)[-1]", 1)[0]

        fixtures = [
            ({"stdout": json.dumps({"reason": "SOURCE_CHANGED", "sensitive": "PRIVATE_SENTINEL"})}, "SOURCE_CHANGED"),
            ({"reason": "DACL_OTHER_PRINCIPAL_REJECTED"}, "DACL_OTHER_PRINCIPAL_REJECTED"),
            ({"stdout": json.dumps({"reason": "PRIVATE_SENTINEL"})}, "UNCLASSIFIED"),
            ("INVALID_JSON_PRIVATE_SENTINEL", "UNCLASSIFIED"),
        ]
        for raw, expected in fixtures:
            with self.subTest(expected=expected):
                payload = raw if isinstance(raw, str) else json.dumps(raw)
                script = (
                    "$raw = @(\n@'\n" + payload + "\n'@\n)\n"
                    "$gatewayExit = 2\n" + fragment
                )
                encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                    capture_output=True, text=True, errors="replace", timeout=25,
                )
                combined = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("AUDIT_CLAIM_FAILURE_CLASS=" + expected, result.stdout)
                self.assertIn("AUDIT_CLAIM_BLOCKED", combined)
                self.assertNotIn("PRIVATE_SENTINEL", combined)

    def test_admission_short_retry_is_bounded_and_fail_closed(self):
        import json
        import shutil
        import subprocess
        text = FILE.read_text()
        section = text.split("      - name: Require owner, current source, dedicated runner and read-only scope", 1)[1].split("      - name: Checkout exact Desktop source", 1)[0]
        lines = section.split("          script: |\n", 1)[1].splitlines()
        source = "\n".join(line[12:] if line.startswith("            ") else line for line in lines)
        self.assertIn("CAPACITY_ADMISSION_CLASS=", source)
        self.assertIn("matches[0].runner_id !== 2", source)
        self.assertIn("matches[0].status !== 'in_progress'", source)
        self.assertIn("for (let attempt = 0; attempt < 3; attempt++)", source)
        self.assertIn("if (attempt === 2 || permanentFailures.length)", source)
        self.assertIn("setTimeout(resolve, 750)", source)
        self.assertNotIn("core.info(jobs)", source)
        self.assertNotIn("core.error(JSON.stringify", source)

        node = shutil.which("node")
        self.assertIsNotNone(node, "GitHub standard Windows and Linux CI runners must have node")
        syntax = subprocess.run([node, "--check", "-"], input=source, text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        harness = r"""
(async () => {
  const source = process.argv[1];
  const scenario = JSON.parse(process.argv[2]);
  const HEAD = '81367c77254cb5bbc175645f3cc825998bbce9cf';
  const RULES = '11e2e86d0283e83247d8058d05bbabe3dd7cc2c2';
  const lines = [];
  let calls = 0;
  const context = {
    eventName: 'workflow_dispatch', actor: 'ericson-j-santos',
    repo: {owner: 'ericson-j-santos', repo: 'desktop-pc24x7-runtime'},
    ref: 'refs/heads/main', sha: HEAD, runId: 123,
    payload: {inputs: {scope: 'READ_ONLY_CAPACITY_NO_INSTALL'}}
  };
  const env = {
    EXPECTED_HEAD: HEAD, EXPECTED_RULES: RULES, GITHUB_RUN_ATTEMPT: '1',
    RUNNER_NAME: 'DESKTOP-PDQK954-runtime'
  };
  const github = {rest: {
    repos: {getBranch: async ({repo}) => ({
      data: {commit: {sha: repo === 'chatgpt-operational-rules' ?
        (scenario.rulesSha || RULES) : (scenario.mainSha || HEAD)}}
    })},
    actions: {listJobsForWorkflowRun: async () => {
      const status = (scenario.statuses || ['in_progress'])[
        Math.min(calls, (scenario.statuses || ['in_progress']).length - 1)];
      calls++;
      return {data: {total_count: 3, jobs: [
        {name: 'Collect Desktop capacity through governed Gateway',
         runner_id: scenario.runnerId ?? 2,
         runner_name: scenario.runnerName || 'DESKTOP-PDQK954-runtime', status},
        {name: 'Stop a capacity probe that never gets a Desktop runner'},
        {name: 'Admit typed owner issue before Desktop scheduling'}
      ]}};
    }}
  }};
  const fn = new (Object.getPrototypeOf(async function(){}).constructor)(
    'github', 'context', 'core', 'require', 'process', 'setTimeout', source);
  let ok = true, error = '';
  try {
    await fn(github, context, {
      info: msg => lines.push(msg), error: msg => lines.push(msg)
    }, name => {
      if (name !== 'os') throw Error('unexpected require');
      return {hostname: () => 'DESKTOP-PDQK954'};
    }, {env}, callback => callback());
  } catch (e) {ok = false; error = e.message}
  process.stdout.write(JSON.stringify({ok, error, calls, lines}));
})().catch(e => {console.error(e); process.exitCode = 2});
"""
        cases = [
            ({"statuses": ["in_progress"]}, True, 1, "CAPACITY_READ_ONLY_ADMISSION_OK"),
            ({"statuses": ["queued", "in_progress"]}, True, 2, "CAPACITY_READ_ONLY_ADMISSION_OK"),
            ({"statuses": ["queued"]}, False, 3, "JOB_STATUS_NOT_IN_PROGRESS"),
            ({"runnerId": 3}, False, 1, "PHYSICAL_RUNNER_ID_CHANGED"),
            ({"mainSha": "c" * 40}, False, 0, "SOURCE_SHA_CHANGED"),
            ({"rulesSha": "d" * 40}, False, 0, "RULES_SHA_CHANGED"),
        ]
        for scenario, admitted, calls, marker in cases:
            with self.subTest(scenario=scenario):
                result = subprocess.run([node, "-e", harness, source, json.dumps(scenario)],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = json.loads(result.stdout)
                self.assertEqual(actual["ok"], admitted)
                self.assertEqual(actual["calls"], calls)
                self.assertTrue(any(marker in line for line in actual["lines"]))
                if not admitted:
                    self.assertEqual(actual["error"], "CAPACITY_SOURCE_RULES_OR_PHYSICAL_RUNNER_CHANGED")
                self.assertFalse(any("private" in line.lower() for line in actual["lines"]))

    def test_ci_automatically_discovers_python_tests(self):
        self.assertIn("python -m pytest -ra", (ROOT / ".github/workflows/ci.yml").read_text())

if __name__ == "__main__":
    unittest.main()
