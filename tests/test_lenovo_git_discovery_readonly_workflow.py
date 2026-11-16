from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/lenovo-git-discovery-readonly.yml"
SOURCE = WORKFLOW.read_text(encoding="utf-8")
SPEC = yaml.load(SOURCE, Loader=yaml.BaseLoader)
JOB = SPEC["jobs"]["discover"]


def test_manual_exact_sha_ci_cost_and_runner_guards():
    assert set(SPEC["on"]) == {"workflow_dispatch"}
    assert set(SPEC["on"]["workflow_dispatch"]["inputs"]) == {"expected_source_sha", "confirmation"}
    assert SPEC["on"]["workflow_dispatch"]["inputs"]["confirmation"]["options"] == ["READ_ONLY_LENOVO_GIT_DISCOVERY"]
    assert SPEC["permissions"] == {"contents": "read", "actions": "read"}
    assert JOB["runs-on"] == ["self-hosted", "Windows", "X64", "pc24x7",
                               "desktop-runtime", "runtime-dev", "desktop-rp23ogs"]
    assert JOB["environment"] == "DEV"
    assert "vars.REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA == github.sha" in JOB["if"]
    admit = JOB["steps"][0]["with"]["script"]
    for token in ("context.actor", "context.ref", "context.sha",
                  "GITHUB_RUN_ATTEMPT", "main.commit.sha", "event:'push'",
                  "head_sha:sha", "LENOVO_GIT_DISCOVERY_CI_GATES_REQUIRED",
                  "'windows-latest'", "'ubuntu-latest'"):
        assert token in admit
    assert JOB["steps"][0]["uses"] == (
        "actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea"
    )


def test_no_checkout_download_install_or_unbounded_search():
    assert len(JOB["steps"]) == 2
    scan = JOB["steps"][1]["run"]
    for forbidden in ("subprocess", "shell=True", "os.system", "os.walk", "rglob(",
                      "curl", "wget", "winget", "choco", "pip install",
                      "shutil.move", "shutil.copy", "mkdir(", "write_text(", "write_bytes("):
        assert forbidden not in scan
    assert "sorted(desktop.glob('app-*'))[:12]" in scan
    assert "LENOVO_GIT_DISCOVERY_HOST_REJECTED" in scan
    assert "file_present_unverified" in scan
    assert "mutation_performed':False" in scan
    assert "actions/checkout@" not in SOURCE


def run_scan(tmp: Path, *, present=False, host="DESKTOP-RP23OGS"):
    if present:
        binary = tmp / "Git" / "cmd" / "git.exe"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"fixture-not-executable")
    env = {
        "COMPUTERNAME": host, "RUNNER_NAME": "DESKTOP-RP23OGS-runtime",
        "ProgramFiles": str(tmp), "ProgramW6432": str(tmp),
        "LOCALAPPDATA": str(tmp), "ProgramData": str(tmp),
        "ProgramFiles(x86)": str(tmp),
    }
    output = io.StringIO()
    with patch.dict(os.environ, env), patch("shutil.which", return_value=None):
        with contextlib.redirect_stdout(output):
            exec(JOB["steps"][1]["run"], {"__name__": "__main__"})
    return json.loads(output.getvalue().strip())


@pytest.mark.parametrize("present,expected", [
    (False, "missing"),
    (True, "file_present_unverified"),
])
def test_readonly_detection_no_execution_and_bounded_result(present, expected):
    with tempfile.TemporaryDirectory() as d:
        receipt = run_scan(Path(d), present=present)
        assert receipt["contract"] == "lenovo-git-discovery-readonly-v1"
        assert receipt["host"] is True and receipt["runner"] is True
        assert receipt["mutation_performed"] is False
        assert receipt["path_lookup_present"] is False
        assert {x["candidate"]: x["state"] for x in receipt["candidates"]}["system"] == expected
        assert run_scan(Path(d), present=present) == receipt


def test_wrong_host_rejected_before_any_local_path_probe():
    with tempfile.TemporaryDirectory() as d:
        with patch("pathlib.Path.is_file", side_effect=AssertionError("read-before-host-guard")):
            with pytest.raises(RuntimeError, match="LENOVO_GIT_DISCOVERY_HOST_REJECTED"):
                run_scan(Path(d), host="DESKTOP-UNAUTHORIZED")
