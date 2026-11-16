from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from scripts import lenovo_git_discovery_readonly as discovery

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / ".github/workflows/lenovo-git-discovery-readonly.yml").read_text("utf-8")
SPEC = yaml.load(SOURCE, Loader=yaml.BaseLoader)
ADMIT = SPEC["jobs"]["admit"]
JOB = SPEC["jobs"]["discover"]


def test_admission_executes_on_hosted_runner_without_physical_filesystem_access():
    assert set(SPEC["on"]) == {"workflow_dispatch"}
    assert set(SPEC["permissions"]) == {"contents", "actions"}
    assert ADMIT["runs-on"] == "ubuntu-latest"
    assert "REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA == github.sha" in ADMIT["if"]
    assert len(ADMIT["steps"]) == 1
    assert ADMIT["steps"][0]["uses"] == "actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea"
    script = ADMIT["steps"][0]["with"]["script"]
    for token in ("context.actor", "context.ref", "context.sha", "GITHUB_RUN_ATTEMPT",
                  "main.commit.sha", "head_sha:sha", "LENOVO_GIT_DISCOVERY_CI_GATES_REQUIRED",
                  "rules_sha"):
        assert token in script
    for forbidden in ("node:fs", "fs.lstatSync(", "child_process", "execFile(", "spawn("):
        assert forbidden not in script


def test_physical_checkout_only_then_session_and_gateway():
    assert JOB["runs-on"] == ["self-hosted", "Windows", "X64", "pc24x7",
                              "desktop-runtime", "runtime-dev", "desktop-rp23ogs"]
    assert JOB["needs"] == "admit"
    assert JOB["if"] == "needs.admit.result == 'success'"
    assert JOB["environment"] == "DEV"
    assert JOB["env"]["DEPLOYMENT_ENV"] == "DEV"
    steps = JOB["steps"]
    assert len(steps) == 4
    assert [x["name"] for x in steps] == [
        "Checkout exact source without credentials",
        "Checkout canonical rules without credentials",
        "Bootstrap governed physical session",
        "Inspect Git candidates only through Command Gateway Risk 1",
    ]
    assert all(x["uses"].startswith("actions/checkout@") for x in steps[:2])
    assert all(x["with"]["persist-credentials"] == "false" for x in steps[:2])
    assert "needs.admit.outputs.rules_sha" in steps[1]["with"]["ref"]
    assert "m['bootstrap']()" not in steps[2]["run"] or "['bootstrap']()" in steps[2]["run"]
    assert "lenovo_control_plane_workflow.py" in steps[2]["run"]
    assert "'--risk','1'" in steps[3]["run"]
    assert "'--expected-head',sha" in steps[3]["run"]
    assert "lenovo_git_discovery_readonly.py" in steps[3]["run"]
    for step in steps[:2]:
        assert "run" not in step and "shell" not in step
    assert "git.exe" not in SOURCE
    assert "node:fs" not in SOURCE


def env_for(root: Path) -> dict[str, str]:
    return {"DEPLOYMENT_ENV": "DEV", "ProgramFiles": str(root),
            "ProgramW6432": str(root), "ProgramFiles(x86)": str(root),
            "LOCALAPPDATA": str(root), "ProgramData": str(root)}


def test_missing_present_and_replay_never_execute_candidate():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        with patch("shutil.which", return_value=None):
            missing = discovery.collect(env_for(root), host="DESKTOP-RP23OGS",
                                        runner="DESKTOP-RP23OGS-runtime")
            assert missing["result"] == "LENOVO_GIT_CANDIDATES_ONLY"
            assert missing["git_verified"] is False
            assert missing["execution_authorized"] is False
            assert missing["mutation_performed"] is False
            assert {item["candidate"]: item["state"] for item in missing["candidates"]}["system"] == "missing"
            git = root / "Git/cmd/git.exe"
            git.parent.mkdir(parents=True)
            git.write_bytes(b"not an executable - never run")
            present = discovery.collect(env_for(root), host="DESKTOP-RP23OGS",
                                        runner="DESKTOP-RP23OGS-runtime")
            assert {item["candidate"]: item["state"] for item in present["candidates"]}["system"] == "file_present_unverified"
            assert discovery.collect(env_for(root), host="DESKTOP-RP23OGS",
                                     runner="DESKTOP-RP23OGS-runtime") == present
            assert git.read_bytes() == b"not an executable - never run"
            assert str(root) not in json.dumps(present)


def test_reject_untrusted_host_runner_and_environment_before_file_probes():
    with tempfile.TemporaryDirectory() as t:
        env = env_for(Path(t))
        with patch.object(discovery, "_state", side_effect=AssertionError("file read before identity")):
            for host, runner, stage in [
                ("WRONG", "DESKTOP-RP23OGS-runtime", "DEV"),
                ("DESKTOP-RP23OGS", "WRONG", "DEV"),
                ("DESKTOP-RP23OGS", "DESKTOP-RP23OGS-runtime", "PROD"),
            ]:
                with pytest.raises(discovery.DiscoveryBlocked, match="HOST_REJECTED"):
                    discovery.collect({**env, "DEPLOYMENT_ENV": stage},
                                      host=host, runner=runner)


def test_bounded_desktop_versions_and_link_rejection_without_following():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        desktop = root / "GitHubDesktop"
        for i in range(20):
            (desktop / f"app-{i:03d}").mkdir(parents=True)
        with patch("shutil.which", return_value=None):
            report = discovery.collect(env_for(root), host="DESKTOP-RP23OGS",
                                       runner="DESKTOP-RP23OGS-runtime")
        assert len(report["candidates"]) <= 31
        binary = root / "Git/cmd/git.exe"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"fixture")
        original = discovery.Path.is_symlink
        def fake_link(path):
            return path == binary or original(path)
        with patch.object(discovery.Path, "is_symlink", fake_link):
            assert discovery._state(binary) == "link_rejected"


def test_gateway_receipt_requires_real_session_and_exact_sha():
    script = JOB["steps"][-1]["run"]
    sha = "a"*40
    target = Path("/isolated/target")
    cwd = os.path.normcase(os.path.realpath(os.path.abspath(str(target)))).replace(os.sep, "/")
    payload = {
        "contract": discovery.CONTRACT, "result": "LENOVO_GIT_CANDIDATES_ONLY",
        "host": discovery.EXPECTED_HOST, "runner_name": discovery.EXPECTED_RUNNER,
        "git_verified": False, "execution_authorized": False,
        "mutation_performed": False, "path_lookup_present": False,
        "candidates": [{"candidate": x[0], "state": "missing"} for x in discovery.CANDIDATES],
    }
    envelope = {
        "action": "run", "risk": 1, "result": "ok",
        "cwd": cwd, "gateway_exit_code": 0, "command_exit_code": 0,
        "state_changed": False, "session_id": "expected-session",
        "correlation_id": "lenovo-control-plane-pickup-321-1",
        "before": {"head": sha}, "after": {"head": sha}, "stdout": json.dumps(payload),
    }
    environment = {
        "GITHUB_WORKSPACE": "/isolated/repo", "TARGET_PATH": str(target),
        "ANCHOR_SHA": sha, "GITHUB_SHA": sha, "SESSION_ID": "expected-session",
        "CORRELATION_ID": "lenovo-control-plane-pickup-321-1",
    }
    def check(data):
        result = SimpleNamespace(returncode=0, stdout=json.dumps(data))
        buf = io.StringIO()
        with patch.dict(os.environ, environment):
            with patch("subprocess.run", return_value=result):
                with contextlib.redirect_stdout(buf):
                    exec(script, {"__name__": "__main__"})
        return buf.getvalue()
    assert json.loads(check(envelope))["result"] == "LENOVO_GIT_CANDIDATES_ONLY"
    for change in ({"session_id": "wrong"}, {"gateway_exit_code": 1},
                   {"before": {"head": "f"*40}}, {"state_changed": True},
                   {"risk": True}, {"stdout": "{}"}):
        with pytest.raises(RuntimeError, match="RECEIPT_REJECTED"):
            check({**envelope, **change})
