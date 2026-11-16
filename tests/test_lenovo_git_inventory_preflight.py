from __future__ import annotations

import contextlib
import io
import os
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "lenovo-installed-inventory-readonly.yml"
SPEC = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
STEPS = SPEC["jobs"]["inventory"]["steps"]
RESOLVE = next(step["run"] for step in STEPS if step["name"] == "Resolve fixed existing Git client")


def execute_resolver(tmp: Path, *, host="DESKTOP-RP23OGS", runner="DESKTOP-RP23OGS-runtime",
                     git_present=False, fake_version="git version 2.49.0.windows.1",
                     recorded_calls=None):
    system = tmp / "system"
    candidate = system / "Git" / "cmd" / "git.exe"
    if git_present:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(b"test-fixture; never execute")
    output_path = tmp / "runner-path-file"
    output_path.write_text("", encoding="utf-8")
    env = {
        "COMPUTERNAME": host,
        "RUNNER_NAME": runner,
        "DEPLOYMENT_ENV": "DEV",
        "ProgramFiles": str(system),
        "ProgramW6432": str(tmp / "system64"),
        "LOCALAPPDATA": str(tmp / "local"),
        "ProgramData": str(tmp / "programdata"),
        "GITHUB_PATH": str(output_path),
    }
    calls = recorded_calls if recorded_calls is not None else []
    def safe_probe(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=fake_version, stderr="")
    with patch.dict(os.environ, env):
        with patch("subprocess.run", side_effect=safe_probe):
            exec(compile(RESOLVE, str(WORKFLOW), "exec"), {"__name__": "__main__"})
    return calls, output_path.read_text(encoding="utf-8"), candidate


def test_permanent_gate_precedes_checkout_and_preserves_git_resolver():
    steps = [x["name"] for x in STEPS]
    assert steps.index("Resolve fixed existing Git client") < steps.index("Checkout exact source without credentials")
    assert "LENOVO_GIT_PREFLIGHT_MISSING" in RESOLVE
    assert "LENOVO_GIT_PREFLIGHT_HOST_REJECTED" in RESOLVE
    assert "LENOVO_GIT_CLIENT_UNAVAILABLE" in RESOLVE
    assert RESOLVE.index("LENOVO_GIT_PREFLIGHT_HOST_REJECTED") < RESOLVE.index("candidates=[")
    assert RESOLVE.index("if not present:") < RESOLVE.index("probe=subprocess.run")
    assert "shell=False" in RESOLVE
    assert "Invoke-WebRequest" not in RESOLVE and "winget" not in RESOLVE
    assert SPEC["jobs"]["inventory"]["if"].find("REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA") >= 0


def test_missing_git_blocks_before_any_executable_or_path_change():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        calls = []
        with pytest.raises(RuntimeError, match="LENOVO_GIT_PREFLIGHT_MISSING"):
            execute_resolver(tmp, git_present=False, recorded_calls=calls)
        assert calls == [], "Absent Git must not be executed"
        assert (tmp / "runner-path-file").read_text(encoding="utf-8") == ""


@pytest.mark.parametrize("host,runner", [
    ("NOT-A-LENOVO", "DESKTOP-RP23OGS-runtime"),
    ("DESKTOP-RP23OGS", "OTHER-RUNNER"),
])
def test_wrong_host_or_runner_blocks_before_file_inspection(host, runner):
    with tempfile.TemporaryDirectory() as t:
        with patch.object(Path, "is_file", side_effect=AssertionError("inspected on wrong host")):
            with pytest.raises(RuntimeError, match="LENOVO_GIT_PREFLIGHT_HOST_REJECTED"):
                execute_resolver(Path(t), host=host, runner=runner)


def test_existing_git_remains_unverified_until_version_gate():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        calls, content, binary = execute_resolver(tmp, git_present=True)
        assert calls == [[str(binary), "--version"]]
        assert content.strip() == str(binary.parent)
        assert (tmp / "runner-path-file").is_file()


def test_invalid_existing_binary_blocks_without_selecting_it():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        with pytest.raises(RuntimeError, match="LENOVO_GIT_CLIENT_UNAVAILABLE"):
            execute_resolver(tmp, git_present=True, fake_version="invalid")
        assert (tmp / "runner-path-file").read_text(encoding="utf-8") == ""


def test_replay_missing_git_does_not_change_state_or_invoke_processes():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for _ in range(2):
            calls = []
            with pytest.raises(RuntimeError, match="LENOVO_GIT_PREFLIGHT_MISSING"):
                execute_resolver(tmp, recorded_calls=calls)
            assert calls == [], "Replay must not execute a program"
            assert (tmp / "runner-path-file").read_text(encoding="utf-8") == ""
