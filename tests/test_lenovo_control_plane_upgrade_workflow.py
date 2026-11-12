from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lenovo_control_plane_upgrade_workflow.py"
WORKFLOW = ROOT / ".github" / "workflows" / "lenovo-control-plane-upgrade-dev.yml"
SPEC = importlib.util.spec_from_file_location("lenovo_control_plane_upgrade_workflow", SCRIPT)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

TARGET = "8" * 40
INSTALLED = "7" * 40


@pytest.fixture
def admitted(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    worktree_root = tmp_path / "worktree-root"
    target = worktree_root / "wt-chat-upgrade-test"
    for path in (
        workspace / "_rules/scripts/command_gateway.py",
        workspace / "_rules/config/command-gateway.policy.json",
        target / "scripts/upgrade_desktop_free_control_plane.py",
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n", encoding="utf-8")
    output = tmp_path / "output.txt"
    env = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": m.EXPECTED_REPOSITORY, "GITHUB_ACTOR": m.EXPECTED_ACTOR,
        "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_NAME": m.EXPECTED_RUNNER, "DEPLOYMENT_ENV": "DEV",
        "CONFIRMATION": m.EXPECTED_CONFIRMATION, "ISSUE_NUMBER": "147",
        "TARGET_SOURCE_SHA": TARGET, "GITHUB_SHA": TARGET, "ANCHOR_SHA": TARGET,
        "EXPECTED_INSTALLED_SHA": INSTALLED,
        "EXPECTED_WATCHDOG_SHA256": "1" * 64, "EXPECTED_UAC_SHA256": "2" * 64,
        "EXPECTED_LAUNCHER_SHA256": "3" * 64,
        "CORRELATION_ID": "rp23ogs-control-plane-upgrade-10-1",
        "TARGET_PATH": str(target), "SESSION_ID": "session-1",
        "GITHUB_WORKSPACE": str(workspace), "GITHUB_OUTPUT": str(output),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(m, "WORKTREE_ROOT", worktree_root.resolve())
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.EXPECTED_HOST)
    return env, output


def gateway_receipt(command_payload):
    gateway = {
        "result": "ok", "gateway_exit_code": 0, "command_exit_code": 0,
        "state_changed": False, "stdout": json.dumps(command_payload),
    }
    return SimpleNamespace(returncode=0, stdout=json.dumps(gateway), stderr="")


def preflight_payload():
    return {
        "result": "UPGRADE_PREFLIGHT_OK", "host": m.EXPECTED_HOST,
        "source_sha": TARGET, "previous_source_sha": INSTALLED,
        "runner_name": m.EXPECTED_RUNNER, "runner_pids": [123],
        "mutation_performed": False, "github_pickup_proven": False,
    }


def test_preflight_uses_fixed_gateway_contract(admitted, monkeypatch):
    calls = []
    monkeypatch.setattr(m.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)) or gateway_receipt(preflight_payload()))
    m.preflight()
    command, kwargs = calls[0]
    assert kwargs["shell"] is False
    assert command[command.index("--risk") + 1] == "1"
    assert command[command.index("--expected-head") + 1] == TARGET
    assert "--preflight-only" in command
    assert command[command.index("--confirm") + 1] == m.EXPECTED_CONFIRMATION
    assert not any(token in command for token in ("cmd", "powershell", "pwsh", "http://", "https://"))


def test_apply_validates_transaction_and_emits_sanitized_receipt(admitted, monkeypatch):
    payload = {
        "result": "CONTROL_PLANE_UPGRADED_PICKUP_PENDING", "host": m.EXPECTED_HOST,
        "source_sha": TARGET, "previous_source_sha": INSTALLED,
        "runner_name": m.EXPECTED_RUNNER, "runner_process_preserved": True,
        "github_pickup_proven": False, "credentials_created": False,
        "production_touched": False, "reboot_performed": False,
    }
    calls = []
    monkeypatch.setattr(m.subprocess, "run", lambda command, **kwargs: calls.append(command) or gateway_receipt(payload))
    m.apply()
    assert calls[0][calls[0].index("--risk") + 1] == "2"
    output = admitted[1].read_text(encoding="utf-8")
    assert "upgrade_result=CONTROL_PLANE_UPGRADED_PICKUP_PENDING" in output
    assert "upgrade_receipt_sha256=" in output


def test_replay_same_sha_is_preflight_only(admitted, monkeypatch):
    monkeypatch.setenv("EXPECTED_INSTALLED_SHA", TARGET)
    payload = preflight_payload()
    payload["previous_source_sha"] = TARGET
    calls = []
    monkeypatch.setattr(m.subprocess, "run", lambda command, **kwargs: calls.append(command) or gateway_receipt(payload))
    m.apply()
    assert calls[0][calls[0].index("--risk") + 1] == "1"
    assert "--preflight-only" in calls[0]
    assert "CONTROL_PLANE_UPGRADE_REPLAY_NOOP" in admitted[1].read_text(encoding="utf-8")


@pytest.mark.parametrize("name,value,reason", [
    ("DEPLOYMENT_ENV", "PROD", "deployment_env_mismatch"),
    ("GITHUB_ACTOR", "someone-else", "github_actor_mismatch"),
    ("GITHUB_REF", "refs/heads/feature", "github_ref_mismatch"),
    ("RUNNER_NAME", "other-runner", "runner_name_mismatch"),
])
def test_identity_controls_fail_closed(admitted, monkeypatch, name, value, reason):
    monkeypatch.setenv(name, value)
    with pytest.raises(m.WorkflowBlocked, match=reason):
        m.preflight()


def test_workflow_has_no_arbitrary_command_or_secret_surface():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "environment: DEV" in text
    assert "cancel-in-progress: false" in text
    assert "DESKTOP-RP23OGS" in text
    assert "desktop-rp23ogs" in text
    assert "UPGRADE-DESKTOP-FREE-CONTROL-PLANE" in text
    assert "persist-credentials: false" in text
    assert "secrets." not in text
    assert "command:" not in text and "url:" not in text and "path:" not in text.split("inputs:", 1)[1].split("permissions:", 1)[0]
