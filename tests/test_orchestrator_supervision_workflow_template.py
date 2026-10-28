"""Parse the disarmed apply workflow without invoking its commands."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/orchestrator-supervised-activation.workflow.yml"
PS_CHECKER = ROOT / "tests/parse_supervision_workflow_powershell.ps1"


class WorkflowTemplateTests(unittest.TestCase):
    def check_js(self, value):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "contract.mjs"
            path.write_text("async function reviewedWorkflow(github, context, core, require) {\n" + value + "\n}\n", encoding="utf-8")
            return subprocess.run(["node", "--check", str(path)], capture_output=True, timeout=30).returncode

    def check_ps(self, value):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "contract.ps1"
            value = re.sub(r"\$\{\{.*?\}\}", "a" * 40, value)
            path.write_text(value, encoding="utf-8")
            return subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File",
                                   str(PS_CHECKER), str(path)], capture_output=True, timeout=30).returncode

    def test_javascript_and_powershell_syntax(self):
        workflow = yaml.load(DOC.read_text(), Loader=yaml.BaseLoader)
        js_count = ps_count = 0
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if step.get("uses", "").startswith("actions/github-script@"):
                    self.assertEqual(self.check_js(step["with"]["script"]), 0)
                    js_count += 1
                if step.get("shell") in ("powershell", "pwsh"):
                    self.assertEqual(self.check_ps(step["run"]), 0)
                    ps_count += 1
        self.assertGreaterEqual(js_count, 3)
        self.assertGreaterEqual(ps_count, 3)

    def test_github_script_function_body_accepts_await_and_return(self):
        self.assertEqual(self.check_js("await Promise.resolve(); return;"), 0)

    def test_parsers_reject_broken_syntax(self):
        self.assertNotEqual(self.check_js("const = ;"), 0)
        self.assertNotEqual(self.check_ps("@{ missing"), 0)

    def test_template_is_disarmed_and_bound_to_reviewed_plan(self):
        self.assertEqual(DOC.parent.name, "docs")
        workflow = yaml.load(DOC.read_text(), Loader=yaml.BaseLoader)
        job = workflow["jobs"]["plan"]
        step = next(s for s in job["steps"] if s.get("id") == "plan")
        plan = json.loads((ROOT / "docs/orchestrator-dev-supervision-activation-e74b89a5.json").read_text())
        self.assertEqual(step["env"]["EXACT_PLAN_APPROVAL"], plan["plan_sha256"])
        self.assertIn("apply_authorized_orchestrator_supervision.py", step["run"])
        self.assertNotIn("python -c", step["run"])
        self.assertNotIn("plan --source-sha", step["run"])
        self.assertIn("context.actor !== 'ericson-j-santos'", DOC.read_text())
        self.assertIn("job?.runner_id !== 2", DOC.read_text())


if __name__ == "__main__":
    unittest.main()
