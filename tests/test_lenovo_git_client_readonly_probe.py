from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml


WORKFLOW = (Path(__file__).resolve().parents[1] / ".github" / "workflows"
            / "lenovo-git-client-readonly-probe.yml")


class LenovoGitClientReadonlyProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.source, Loader=yaml.BaseLoader)
        cls.job = cls.workflow["jobs"]["probe"]
        cls.probe = cls.job["steps"][1]["run"]

    def test_scope_is_branch_bound_readonly_and_exact_runner(self):
        self.assertEqual(set(self.workflow["on"]), {"push"})
        self.assertEqual(
            self.workflow["on"]["push"]["branches"],
            ["repair/lenovo-git-client-probe-151"],
        )
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(
            self.job["runs-on"],
            ["self-hosted", "Windows", "X64", "pc24x7",
             "desktop-runtime", "runtime-dev", "desktop-rp23ogs"],
        )
        self.assertIn("DESKTOP-RP23OGS-runtime", self.source)
        self.assertIn("DESKTOP-RP23OGS", self.source)

    def test_probe_is_bounded_and_forbids_install_or_unrestricted_search(self):
        for required in (
            "ProgramFiles", "ProgramW6432", "LOCALAPPDATA", "ProgramData",
            "GitHubDesktop", "Visual Studio", "RUNNER_TEMP", "git.exe",
            "shell=False", "mutation_performed", "candidate_id",
        ):
            self.assertIn(required, self.probe)
        for forbidden in (
            "rglob(", "os.walk", "where.exe", "Invoke-WebRequest", "curl",
            "wget", "winget", "choco", "Start-Process", "subprocess.Popen",
        ):
            self.assertNotIn(forbidden, self.probe)

    def test_positive_reports_only_logical_candidate_and_version(self):
        environment = {
            "ProgramFiles": "/fixed",
            "RUNNER_NAME": "DESKTOP-RP23OGS-runtime",
        }
        expected = Path("/fixed/Git/cmd/git.exe")
        fake = SimpleNamespace(returncode=0, stdout="git version 2.52.0.windows.1")
        output = io.StringIO()
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(Path, "is_file", lambda candidate: candidate == expected), \
                patch.object(Path, "is_symlink", return_value=False), \
                patch.object(subprocess, "run", return_value=fake), \
                contextlib.redirect_stdout(output):
            exec(self.probe, {"__name__": "__main__"})
        report = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(report["candidates"], [{
            "candidate_id": "PROGRAM_FILES_GIT_CMD",
            "version": "git version 2.52.0.windows.1",
        }])
        self.assertFalse(report["mutation_performed"])
        self.assertNotIn("/fixed", output.getvalue())

    def test_negative_fails_closed_when_no_candidate_exists(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"RUNNER_NAME": "DESKTOP-RP23OGS-runtime"}, clear=True), \
                contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(
                    RuntimeError, "LENOVO_GIT_CLIENT_NOT_FOUND_IN_BOUNDED_PATHS"):
                exec(self.probe, {"__name__": "__main__"})
        report = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["mutation_performed"])


if __name__ == "__main__":
    unittest.main()
