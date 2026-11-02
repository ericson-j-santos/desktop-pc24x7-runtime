"""Negative controls for the fixed local GitHub auth recovery action."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import importlib.util
import json
import subprocess
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "orchestrator_local_gh_auth_recovery.py"
SPEC = importlib.util.spec_from_file_location("orchestrator_local_gh_auth_recovery", SOURCE)
assert SPEC and SPEC.loader
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


def invoke(login_result: subprocess.CompletedProcess[str]) -> tuple[int, dict, list[str]]:
    output = StringIO()
    with mock.patch.object(recovery, "safe_context", return_value=True), \
         mock.patch.object(recovery, "check_source", return_value=True), \
         mock.patch.object(recovery.shutil, "which", return_value="gh.exe"), \
         mock.patch.object(recovery, "owner_validated", side_effect=[False, True]), \
         mock.patch.object(recovery, "gh_environment", return_value={"APPDATA": "safe"}), \
         mock.patch.object(recovery.subprocess, "run", return_value=login_result) as run, \
         redirect_stdout(output):
        code = recovery.recover("a" * 40, recovery.CONFIRM)
    return code, json.loads(output.getvalue()), run.call_args.args[0]


def test_fixed_web_login_and_sanitized_success() -> None:
    code, result, command = invoke(subprocess.CompletedProcess([], 0, "ONE-TIME-CODE", "secret"))
    assert code == 0
    assert result["state"] == "github_owner_validated"
    assert result["credential_material_emitted"] is False
    assert command == [
        "gh.exe", "auth", "login", "--hostname", "github.com", "--web",
        "--clipboard", "--git-protocol", "https", "--scopes", "repo",
    ]
    assert "ONE-TIME-CODE" not in json.dumps(result)
    assert "secret" not in json.dumps(result)


def test_failed_web_login_never_emits_code() -> None:
    output = StringIO()
    with mock.patch.object(recovery, "safe_context", return_value=True), \
         mock.patch.object(recovery, "check_source", return_value=True), \
         mock.patch.object(recovery.shutil, "which", return_value="gh.exe"), \
         mock.patch.object(recovery, "owner_validated", return_value=False), \
         mock.patch.object(recovery.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "CODE", "TOKEN")), \
         redirect_stdout(output):
        code = recovery.recover("a" * 40, recovery.CONFIRM)
    assert code == 2
    assert json.loads(output.getvalue())["state"] == "browser_authorization_incomplete"
    assert "CODE" not in output.getvalue()
    assert "TOKEN" not in output.getvalue()


def test_invalid_confirmation_stops_before_login() -> None:
    output = StringIO()
    with mock.patch.object(recovery.shutil, "which") as which, redirect_stdout(output):
        code = recovery.recover("a" * 40, "wrong")
    assert code == 2
    assert json.loads(output.getvalue())["state"] == "governed_context_invalid"
    which.assert_not_called()
