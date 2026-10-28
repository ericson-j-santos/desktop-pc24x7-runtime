"""Negative controls for the local GitHub auth diagnostic."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import os
import tempfile
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "orchestrator_local_gh_auth_diagnostic",
    SCRIPTS / "orchestrator_local_gh_auth_diagnostic.py",
)
assert spec and spec.loader
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class AuthClassificationTests(unittest.TestCase):
    def payload(self, state="success", login="ericson-j-santos", active=True):
        return {"hosts": {"github.com": [
            {"state": state, "login": login, "active": active}
        ]}}

    def test_no_credential(self):
        self.assertEqual(diagnostic.classify_auth_status({"hosts": {}}, 1), "credential_unavailable")
        self.assertEqual(diagnostic.classify_auth_status(self.payload(active=False), 1), "credential_unavailable")

    def test_invalid_and_unavailable(self):
        self.assertEqual(diagnostic.classify_auth_status(self.payload(state="error"), 1), "authentication_invalid")
        self.assertEqual(diagnostic.classify_auth_status(self.payload(state="refresh_expired"), 1), "authentication_invalid")
        self.assertEqual(diagnostic.classify_auth_status(self.payload(state="timeout"), 1), "github_endpoint_unavailable")
        self.assertEqual(diagnostic.classify_auth_status(None, 1), "auth_status_unavailable")

    def test_account_mismatch(self):
        self.assertEqual(diagnostic.classify_auth_status(self.payload(login="different-user"), 0), "account_mismatch")

    def test_unavailable_status_uses_token_probe_without_capturing_token(self):
        status = subprocess.CompletedProcess([], 1, "", "untrusted stderr")
        token = subprocess.CompletedProcess([], 1, None, None)
        with patch.object(diagnostic.bootstrap, "find_gh", return_value="gh"), \
             patch.object(diagnostic.bootstrap, "gh_env", return_value={}), \
             patch.object(diagnostic.subprocess, "run", side_effect=[status, token]) as run:
            observed = diagnostic.diagnose_auth()
        self.assertEqual(observed, ("credential_unavailable", True, False))
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_same_profile_config_recovers_owner_without_token_output(self):
        version = subprocess.CompletedProcess([], 0, "gh version 2.82.0\n", "")
        token = subprocess.CompletedProcess([], 0, None, None)
        api = subprocess.CompletedProcess([], 0, "ericson-j-santos\n", "")
        with tempfile.TemporaryDirectory() as root:
            appdata = pathlib.Path(root) / "AppData" / "Roaming"
            appdata.mkdir(parents=True)
            with patch.dict(os.environ, {"USERPROFILE": root, "APPDATA": str(appdata),
                                       "GH_CONFIG_DIR": str(pathlib.Path(root) / "wrong")}), \
                 patch.object(diagnostic.bootstrap, "find_gh", return_value="gh"), \
                 patch.object(diagnostic.bootstrap, "gh_env", return_value={}), \
                 patch.object(diagnostic.subprocess, "run", side_effect=[version, token, api]) as run:
                observed = diagnostic.probe_same_profile_config()
        self.assertEqual(observed["same_profile_auth"], "owner_validated")
        self.assertTrue(observed["gh_config_dir_set"])
        self.assertEqual(observed["gh_version"], "2.82.0")
        self.assertEqual(run.call_args_list[1].kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args_list[1].kwargs["stderr"], subprocess.DEVNULL)

    def test_owner_token_can_be_present_but_inactive(self):
        version = subprocess.CompletedProcess([], 0, "gh version 2.100.0\n", "")
        inactive = subprocess.CompletedProcess([], 1, None, None)
        owner = subprocess.CompletedProcess([], 0, None, None)
        with tempfile.TemporaryDirectory() as root:
            appdata = pathlib.Path(root) / "AppData" / "Roaming"
            appdata.mkdir(parents=True)
            with patch.dict(os.environ, {"USERPROFILE": root, "APPDATA": str(appdata)}), \
                 patch.object(diagnostic.bootstrap, "find_gh", return_value="gh"), \
                 patch.object(diagnostic.bootstrap, "gh_env", return_value={}), \
                 patch.object(diagnostic.subprocess, "run", side_effect=[version, inactive, owner]) as run:
                observed = diagnostic.probe_same_profile_config()
        self.assertEqual(observed["same_profile_auth"], "owner_credential_inactive")
        self.assertTrue(observed["owner_token_present_but_inactive"])
        self.assertEqual(run.call_args_list[2].kwargs["stdout"], subprocess.DEVNULL)

    def test_git_helper_owner_and_registry_without_exporting_secret(self):
        secret = "dummy-test-token-never-export"
        helper = subprocess.CompletedProcess([], 0,
            "protocol=https\nhost=github.com\nusername=ericson-j-santos\npassword=" + secret + "\n", "")
        responses = [
            io.BytesIO(json.dumps({"login": "ericson-j-santos"}).encode()),
            io.BytesIO(json.dumps({"total_count": 0, "runners": []}).encode()),
        ]
        with patch.object(diagnostic.subprocess, "run", return_value=helper) as run, \
             patch.object(diagnostic.urllib.request, "urlopen", side_effect=responses):
            report = diagnostic.probe_git_credential()
        self.assertTrue(report["owner_validated"])
        self.assertEqual(report["registry_status"], "observed")
        self.assertEqual(report["runner_count"], 0)
        self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(run.call_args.kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(run.call_args.kwargs["env"]["GCM_INTERACTIVE"], "Never")

    def test_git_helper_rejects_other_owner_before_registry(self):
        helper = subprocess.CompletedProcess([], 0,
            "protocol=https\nhost=github.com\npassword=dummy-test-token\n", "")
        with patch.object(diagnostic.subprocess, "run", return_value=helper), \
             patch.object(diagnostic.urllib.request, "urlopen",
                          return_value=io.BytesIO(b'{"login":"different-account"}')) as api:
            report = diagnostic.probe_git_credential()
        self.assertEqual(report["credential_status"], "account_mismatch")
        self.assertFalse(report["owner_validated"])
        self.assertEqual(api.call_count, 1)

    def test_health_supervisor_queries_correct_task_and_compares_sid_privately(self):
        sid = "S-1-5-21-111-222-333-1001"
        with tempfile.TemporaryDirectory() as local:
            root = pathlib.Path(local) / "DesktopPC24x7" / "RuntimeSupervisor"
            root.mkdir(parents=True)
            (root / "install-evidence.json").write_text(json.dumps({"source_sha": "a" * 40}))
            (root / "evidence.json").write_text(json.dumps({
                "timestamp": diagnostic.datetime.now().astimezone().isoformat(), "status": "ok"}))
            xml = ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                   '<RegistrationInfo><URI>\\Automation\\DesktopPc24x7RuntimeHealthSupervisor</URI></RegistrationInfo>'
                   '<Principals><Principal><UserId>' + sid + '</UserId><LogonType>S4U</LogonType></Principal></Principals>'
                   '<Triggers><BootTrigger/></Triggers><Actions><Exec><Arguments>"' +
                   str(root / "run-supervisor.py") + '"</Arguments></Exec></Actions></Task>').encode()
            query = subprocess.CompletedProcess([], 0, xml, b"")
            who = subprocess.CompletedProcess([], 0, ('"private-user","' + sid + '"').encode(), b"")
            with patch.dict(os.environ, {"LOCALAPPDATA": local}), \
                 patch.object(diagnostic.subprocess, "run", side_effect=[query, who]) as run:
                report = diagnostic.probe_health_supervisor()
        self.assertEqual(report["task_query_status"], "observed")
        self.assertTrue(report["process_sid_matches_task_principal"])
        self.assertTrue(report["task_action_matches_installed_launcher"])
        self.assertTrue(report["fresh_300s"])
        self.assertNotIn(sid, json.dumps(report))
        self.assertIn("DesktopPc24x7RuntimeHealthSupervisor", run.call_args_list[0].args[0][3])

    def test_owner_candidate_requires_api_readback(self):
        self.assertEqual(diagnostic.classify_auth_status(self.payload(), 0), "owner_candidate")
        status = subprocess.CompletedProcess([], 0, json.dumps(self.payload()), "secret stderr")
        api = subprocess.CompletedProcess([], 0, "ericson-j-santos\n", "secret stderr")
        with patch.object(diagnostic.bootstrap, "find_gh", return_value="gh"), \
             patch.object(diagnostic.bootstrap, "gh_env", return_value={"GH_TOKEN": "secret", "GITHUB_TOKEN": "secret"}), \
             patch.object(diagnostic.subprocess, "run", side_effect=[status, api]) as run:
            with redirect_stdout(io.StringIO()) as output:
                observed = diagnostic.diagnose_auth()
        self.assertEqual(observed, ("owner_validated", True, True))
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("GH_TOKEN", run.call_args.kwargs["env"])
        self.assertNotIn("GITHUB_TOKEN", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["env"]["GH_HOST"], "github.com")


if __name__ == "__main__":
    unittest.main()
