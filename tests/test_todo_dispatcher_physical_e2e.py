from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import todo_dispatcher_physical_e2e as e2e


RUNTIME_SHA = "a" * 40
RULES_SHA = "b" * 40


def _payload() -> dict:
    return {
        "contract": "github-hourly-todo-bridge-e2e",
        "head_sha": RULES_SHA,
        "positive_event_id": "evt-positive",
        "positive_idempotency_key": "1" * 64,
        "selected_idempotency_key": "1" * 64,
        "positive_continuation_state": "COMPLETED",
        "positive_event_count": 1,
        "positive_continuation_count": 1,
        "first_cycle_requested": 1,
        "skipped_by_capacity": 1,
        "lower_continuation_count": 0,
        "replay_cycle_requested": 0,
        "replay_existing": 1,
        "scheduler_replay_duplicate": True,
        "negative_requested": 0,
        "negative_skipped_untyped": 1,
        "negative_continuation_count": 0,
        "ready": True,
    }


def test_runtime_identity_is_fail_closed() -> None:
    e2e.validate_runtime_identity(
        {"COMPUTERNAME": e2e.EXPECTED_HOST, "RUNNER_NAME": e2e.EXPECTED_RUNNER}
    )

    with pytest.raises(e2e.DispatcherE2EError, match="unexpected_runtime_host"):
        e2e.validate_runtime_identity(
            {"COMPUTERNAME": "NOTERI", "RUNNER_NAME": e2e.EXPECTED_RUNNER}
        )

    with pytest.raises(e2e.DispatcherE2EError, match="unexpected_runtime_runner"):
        e2e.validate_runtime_identity(
            {"COMPUTERNAME": e2e.EXPECTED_HOST, "RUNNER_NAME": "other"}
        )


def test_dispatcher_evidence_requires_pareto_replay_and_negative_control() -> None:
    payload = _payload()
    e2e.validate_dispatcher_evidence(payload, RULES_SHA)

    payload["lower_continuation_count"] = 1
    with pytest.raises(
        e2e.DispatcherE2EError, match="lower_not_dispatched"
    ):
        e2e.validate_dispatcher_evidence(payload, RULES_SHA)


def test_physical_adapter_wraps_canonical_harness_and_sanitizes_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules_root = tmp_path / "rules"
    harness = rules_root / e2e.HARNESS_RELATIVE
    harness.parent.mkdir(parents=True)
    harness.write_text("# canonical harness\n", encoding="utf-8")
    output = tmp_path / "artifacts" / "evidence.json"

    monkeypatch.setattr(
        e2e,
        "git_sha",
        lambda root: RUNTIME_SHA if root == e2e.ROOT else RULES_SHA,
    )

    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["cwd"] = kwargs.get("cwd")
        observed["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(_payload()) + "\n",
            stderr="",
        )

    monkeypatch.setattr(e2e.subprocess, "run", fake_run)

    result = e2e.run_physical_e2e(
        expected_runtime_sha=RUNTIME_SHA,
        expected_rules_sha=RULES_SHA,
        rules_root=rules_root,
        correlation_id="corr-test",
        output=output,
        env={
            "COMPUTERNAME": e2e.EXPECTED_HOST,
            "RUNNER_NAME": e2e.EXPECTED_RUNNER,
        },
    )

    assert result["result"] == "TODO_DISPATCHER_PHYSICAL_E2E_PASSED"
    assert result["runtime_sha"] == RUNTIME_SHA
    assert result["rules_sha"] == RULES_SHA
    assert result["independent_readback"] is True
    assert result["secrets_exposed"] is False
    assert observed["cwd"] == rules_root
    assert str(rules_root) in str((observed["env"] or {}).get("PYTHONPATH", ""))
    written = output.read_text(encoding="utf-8")
    assert "TODO_DISPATCHER_PHYSICAL_E2E_PASSED" in written
    assert "TODO_GATEWAY_TOKEN" not in written


def test_physical_workflow_is_sha_pinned_and_governed() -> None:
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "todo-dispatcher-physical-e2e.yml"
    ).read_text(encoding="utf-8")

    assert "5d1f603241dde37a597d2b7bdc5e07425db7b451" in workflow
    assert "session_launcher.py" in workflow
    assert "command_gateway.py" in workflow
    assert "SESSION_LAUNCH_OK" in workflow
    assert "state_validated" in workflow
    assert '"--risk", "2"' in workflow
    assert "DESKTOP-PDQK954" in workflow
    assert "runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev]" in workflow
    assert "TODO dispatcher physical E2E on Desktop" in workflow
    assert "name: Physical runner queue watchdog" in workflow
    assert 'STALL_AFTER_SECONDS: "60"' in workflow
    assert "scripts/progress_watchdog.py" in workflow
    assert "cancelWorkflowRun" in workflow
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in workflow
    assert "artifacts\\todo-dispatcher-physical-e2e\\evidence.json" in workflow
    assert "push:" in workflow
    assert "- main" in workflow
    assert "python scripts/todo_dispatcher_physical_e2e.py" not in workflow
