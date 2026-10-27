from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lenovo_control_plane_workflow.py"
SPEC = importlib.util.spec_from_file_location("lenovo_control_plane_workflow", SCRIPT)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def valid_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sha: str) -> None:
    values = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": m.EXPECTED_REPOSITORY,
        "GITHUB_SHA": sha,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_REF_NAME": "fix/lenovo-pickup-no-ps1-20261027",
        "GITHUB_WORKSPACE": str(tmp_path / "workspace"),
        "GITHUB_OUTPUT": str(tmp_path / "outputs.txt"),
        "RUNNER_NAME": m.EXPECTED_RUNNER,
        "CORRELATION_ID": "lenovo-control-plane-pickup-123-2",
        "EVIDENCE_REL": m.EXPECTED_EVIDENCE_REL,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.EXPECTED_HOST)


def create_governed_files(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    rules = workspace / "_rules"
    (rules / "scripts").mkdir(parents=True)
    (rules / "config").mkdir(parents=True)
    (rules / "scripts" / "session_launcher.py").write_text("# launcher\n", encoding="utf-8")
    (rules / "scripts" / "command_gateway.py").write_text("# gateway\n", encoding="utf-8")
    (rules / "config" / "command-gateway.policy.json").write_text("{}\n", encoding="utf-8")
    target = tmp_path / "target"
    (target / "scripts").mkdir(parents=True)
    (target / "scripts" / "lenovo_control_plane_pickup.py").write_text("# probe\n", encoding="utf-8")
    return workspace, target


def test_bootstrap_uses_python_without_shell_and_writes_fixed_outputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sha = "a" * 40
    valid_env(monkeypatch, tmp_path, sha)
    workspace, target = create_governed_files(tmp_path)
    payload = {
        "result": "SESSION_LAUNCH_OK",
        "state_validated": True,
        "head": sha,
        "runner_version_preflight": {"ok": True},
        "target_path": str(target),
        "session_id": "session-123",
    }
    observed: dict = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, json.dumps(payload) + "\n", "")

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    m.bootstrap()

    assert observed["command"][0] == sys.executable
    assert "--require-runner-version-preflight" in observed["command"]
    assert observed["kwargs"]["shell"] is False
    assert Path(workspace / "_rules" / "scripts" / "session_launcher.py") == Path(observed["command"][1])
    outputs = (tmp_path / "outputs.txt").read_text(encoding="utf-8")
    assert f"target_path={target}" in outputs
    assert "session_id=session-123" in outputs
    assert f"anchor_sha={sha}" in outputs


def test_bootstrap_rejects_wrong_runner_before_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    valid_env(monkeypatch, tmp_path, "a" * 40)
    monkeypatch.setenv("RUNNER_NAME", "wrong-runner")
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("subprocess must not run"),
    )
    with pytest.raises(m.WorkflowBlocked, match="runner_name_mismatch"):
        m.bootstrap()


def test_prove_invokes_only_fixed_gateway_without_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sha = "b" * 40
    valid_env(monkeypatch, tmp_path, sha)
    _, target = create_governed_files(tmp_path)
    monkeypatch.setenv("ANCHOR_SHA", sha)
    monkeypatch.setenv("TARGET_PATH", str(target))
    monkeypatch.setenv("SESSION_ID", "session-456")
    observed: dict = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[None]:
        observed["command"] = command
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    m.prove()

    command = observed["command"]
    assert command[0] == sys.executable
    assert command[1].endswith("command_gateway.py")
    assert "--session-id" in command
    assert "session-456" in command
    assert "--expected-source-sha" in command
    assert sha in command
    assert observed["kwargs"]["shell"] is False
