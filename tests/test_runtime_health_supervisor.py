from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "runtime_health_supervisor", ROOT / "scripts" / "runtime_health_supervisor.py"
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def config() -> dict:
    return {
        "host": m.EXPECTED_HOST,
        "max_attempts": 2,
        "cooldown_seconds": 60,
        "targets": [{"name": "runner", "kind": "runner"}],
    }


def test_healthy_probe_resets_breaker() -> None:
    state = {"targets": {"runner": {"attempts": 2, "opened_at_epoch": 10}}}
    evidence, updated = m.run_cycle(
        config(), state, apply=True, epoch=20, probe_fn=lambda _: {"healthy": True}
    )
    assert evidence["status"] == m.STATUS_OK
    assert updated["targets"]["runner"]["attempts"] == 0
    assert updated["targets"]["runner"]["opened_at_epoch"] == 0


def test_recovery_is_bounded_and_opens_breaker() -> None:
    state: dict = {}
    recoveries: list[str] = []

    def recover(target: dict) -> dict:
        recoveries.append(target["name"])
        return {"action": "test", "exit_code": 0}

    for epoch in (10, 20):
        evidence, state = m.run_cycle(
            config(), state, apply=True, epoch=epoch,
            probe_fn=lambda _: {"healthy": False}, recover_fn=recover,
        )
        assert evidence["status"] == m.STATUS_INFRA_UNAVAILABLE
    evidence, state = m.run_cycle(
        config(), state, apply=True, epoch=30,
        probe_fn=lambda _: {"healthy": False}, recover_fn=recover,
    )
    assert recoveries == ["runner", "runner"]
    assert evidence["targets"][0]["reason"] == "attempt_limit_reached"
    assert state["targets"]["runner"]["opened_at_epoch"] == 30


def test_open_breaker_prevents_blind_retry() -> None:
    state = {"targets": {"runner": {"attempts": 2, "opened_at_epoch": 100}}}
    evidence, _ = m.run_cycle(
        config(), state, apply=True, epoch=120,
        probe_fn=lambda _: {"healthy": False},
        recover_fn=lambda _: pytest.fail("recovery must not run"),
    )
    assert evidence["targets"][0]["reason"] == "circuit_breaker_open"


def test_arbitrary_commands_are_rejected() -> None:
    value = config()
    value["targets"][0]["command"] = "whoami"
    with pytest.raises(m.SupervisorError, match="arbitrarios"):
        m.validate_config(value)


def test_http_probe_rejects_non_loopback() -> None:
    with pytest.raises(m.SupervisorError, match="loopback"):
        m.probe_http("https://example.com/health")


def test_canary_uses_materialized_worktree_and_gateway() -> None:
    workflow = (ROOT / ".github" / "workflows" / "runtime-canary.yml").read_text(
        encoding="utf-8"
    )
    assert 'runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev, desktop-pdqk954]' in workflow
    assert "--require-runner-version-preflight" in workflow
    assert "steps.session.outputs.target_path" in workflow
    assert "scripts\\command_gateway.py" in workflow
    assert "schedule:" in workflow
    assert "pull_request:" in workflow
    assert "github.event.pull_request.head.sha || github.sha" in workflow
    assert workflow.count("shell: powershell") == 2
    assert "shell: pwsh" not in workflow


def test_installer_contract_is_s4u_boot_and_minute_interval() -> None:
    installer = (ROOT / "scripts" / "install_runtime_health_supervisor.py").read_text(
        encoding="utf-8"
    )
    assert 'TASK_LEAF = "DesktopPc24x7RuntimeHealthSupervisor"' in installer
    assert "definition.Triggers.Create(8)" in installer
    assert 'trigger.Repetition.Interval = "PT1M"' in installer
    assert "principal.LogonType = 2" in installer
    assert "task_readback_failed" in installer


def test_canary_draft_gate_and_queue_watchdog_are_fail_closed() -> None:
    workflow = (ROOT / ".github" / "workflows" / "runtime-canary.yml").read_text(
        encoding="utf-8"
    )
    assert "types: [opened, synchronize, reopened, ready_for_review]" in workflow
    assert "group: ${{ github.event_name == 'pull_request' && format('pc24x7-runtime-canary-pr-{0}', github.event.number) || 'pc24x7-runtime-canary' }}" in workflow
    gate = (
        "github.event_name != 'pull_request' || "
        "(!github.event.pull_request.draft && "
        "github.event.pull_request.head.repo.full_name == github.repository)"
    )
    assert workflow.count(gate) == 2
    assert "name: Runtime canary queue watchdog" in workflow
    assert 'STALL_AFTER_SECONDS: "300"' in workflow
    assert "EXPECTED_RUNNER: DESKTOP-PDQK954-runtime" in workflow
    assert "CANARY_JOB_NOT_UNIQUE" in workflow
    assert "progress_watchdog.py" in workflow
    assert "actions: write" in workflow
    assert "cancelWorkflowRun" in workflow
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in workflow
    assert "const anchor = new Date();" in workflow
    assert "run.data.created_at" not in workflow
    assert "last_material_progress_at: anchor.toISOString()" in workflow


def test_installer_contract_is_s4u_boot_and_minute_interval() -> None:
    installer = (ROOT / "scripts" / "install_runtime_health_supervisor.py").read_text(
        encoding="utf-8"
    )
    assert 'TASK_LEAF = "DesktopPc24x7RuntimeHealthSupervisor"' in installer
    assert "definition.Triggers.Create(8)" in installer
    assert 'trigger.Repetition.Interval = "PT1M"' in installer
    assert "principal.LogonType = 2" in installer
    assert "task_readback_failed" in installer



def test_canary_queue_is_isolated_per_pr_without_cancelling_active_runs() -> None:
    workflow = (ROOT / ".github" / "workflows" / "runtime-canary.yml").read_text(encoding="utf-8")
    assert "group: ${{ github.event_name == 'pull_request' && format('pc24x7-runtime-canary-pr-{0}', github.event.number) || 'pc24x7-runtime-canary' }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev, desktop-pdqk954]" in workflow

def test_canary_pins_immutable_rules_from_canonical_main() -> None:
    workflow = (ROOT / '.github' / 'workflows' / 'runtime-canary.yml').read_text(encoding='utf-8')
    canary = workflow.split('  queue_watchdog:', 1)[0]
    assert 'id: physical_rules' in canary
    assert "repo: 'chatgpt-operational-rules'" in canary
    assert 'core.setFailed(\'CANARY_RULES_SHA_UNVERIFIED\')' in canary
    assert 'ref: ${{ steps.physical_rules.outputs.sha }}' in canary
    assert 'persist-credentials: false' in canary
    assert canary.index('Checkout immutable canonical operational rules') < canary.index('Materialize governed session')
    assert canary.count('CANARY_RULES_SHA_MISMATCH') == 2
    assert canary.count("$rulesSha -ne '${{ steps.physical_rules.outputs.sha }}'") == 2
    assert r'C:\dev\chatgpt-operational-rules' not in canary
    assert "Join-Path $rulesRoot 'scripts\\session_launcher.py'" in canary
    assert "Join-Path $rulesRoot 'scripts\\command_gateway.py'" in canary
    assert "Join-Path $rulesRoot 'config\\command-gateway.policy.json'" in canary
    assert '--require-runner-version-preflight' in canary
