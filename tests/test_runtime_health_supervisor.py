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
    assert "pull_request:" not in workflow.split("permissions:", 1)[0]
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


def test_canary_event_gate_and_queue_watchdog_are_fail_closed() -> None:
    workflow = (ROOT / ".github" / "workflows" / "runtime-canary.yml").read_text(
        encoding="utf-8"
    )
    assert "pull_request:" not in workflow.split("permissions:", 1)[0]
    assert "workflow_dispatch:" in workflow.split("permissions:", 1)[0]
    assert "group: pc24x7-runtime-canary" in workflow
    gate = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
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



def test_canary_queue_does_not_cancel_active_runs() -> None:
    workflow = (ROOT / ".github" / "workflows" / "runtime-canary.yml").read_text(encoding="utf-8")
    assert "group: pc24x7-runtime-canary" in workflow
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
    assert canary.count('function Assert-PinnedRulesSha') == 2
    assert canary.count('CANARY_RULES_SHA_MISMATCH') == 4
    assert canary.count('CANARY_RULES_NEGATIVE_REJECTED') == 2
    assert canary.count('CANARY_RULES_NEGATIVE_ACCEPTED') == 2
    assert canary.count("$expectedRulesSha = '${{ steps.physical_rules.outputs.sha }}'") == 2
    assert canary.count('Assert-PinnedRulesSha -Observed $rulesSha -Expected $invalidRulesSha') == 2
    assert canary.count('Assert-PinnedRulesSha -Observed $rulesSha -Expected $expectedRulesSha') == 2
    assert r'C:\dev\chatgpt-operational-rules' not in canary
    assert "Join-Path $rulesRoot 'scripts\\session_launcher.py'" in canary
    assert "Join-Path $rulesRoot 'scripts\\command_gateway.py'" in canary
    assert "Join-Path $rulesRoot 'config\\command-gateway.policy.json'" in canary
    assert '--require-runner-version-preflight' in canary

def test_http_probe_classifies_refused_without_leaking_details(monkeypatch) -> None:
    import errno
    import urllib.error

    def refused(*_args, **_kwargs):
        raise urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "private details"))

    monkeypatch.setattr(m.urllib.request, "urlopen", refused)
    result = m.probe_http("http://127.0.0.1:8787/readyz")
    assert result == {
        "healthy": False, "reason": "URLError", "failure_class": "connection_refused"
    }
    assert "private details" not in str(result)


def test_http_probe_classifies_timeout_and_5xx(monkeypatch) -> None:
    import errno
    import urllib.error

    def timeout(*_args, **_kwargs):
        raise urllib.error.URLError(TimeoutError(errno.ETIMEDOUT, "private timeout"))

    monkeypatch.setattr(m.urllib.request, "urlopen", timeout)
    assert m.probe_http("http://127.0.0.1:8787/readyz")["failure_class"] == "timeout"

    def bad_status(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "http://127.0.0.1:8787/readyz", 503, "private response", None, None
        )

    monkeypatch.setattr(m.urllib.request, "urlopen", bad_status)
    result = m.probe_http("http://127.0.0.1:8787/readyz")
    assert result["status_code"] == 503
    assert result["failure_class"] == "http_non_2xx"
    assert "private response" not in str(result)


def test_readonly_supervisor_never_writes_operational_state(tmp_path, monkeypatch) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_text('{"existing":true}', encoding="utf-8")
    state = {"targets": {"runner": {"attempts": 99}}}

    def forbidden_write(*_args, **_kwargs):
        pytest.fail("read-only probe must not write operational state")

    monkeypatch.setattr(m, "atomic_json", forbidden_write)
    assert m.persist_supervisor_state(state_path, state, apply=False) is False
    assert state_path.read_text(encoding="utf-8") == '{"existing":true}'


def test_recovery_mode_state_persistence_remains_enabled(tmp_path, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(m, "atomic_json", lambda *args: calls.append(args))
    state_path = tmp_path / "state.json"
    state = {"targets": {}}
    assert m.persist_supervisor_state(state_path, state, apply=True) is True
    assert calls == [(state_path, state)]


def test_readonly_workflow_is_manual_owner_only_and_pins_current_rules() -> None:
    workflow = (ROOT / ".github" / "workflows" / "pc24x7-orchestrator-supervisor-readonly.yml").read_text(encoding="utf-8")
    trigger = workflow.split("permissions:", 1)[0]
    assert "workflow_dispatch:" in trigger
    assert "schedule:" not in trigger and "push:" not in trigger
    assert "context.actor !== context.repo.owner" in workflow
    assert "main.commit.sha !== context.sha" in workflow
    assert "READONLY_MANUAL_SCOPE_DENIED" in workflow
    assert "canonical_rules_sha" in workflow
    assert "ref: ${{ needs.contract.outputs.canonical_rules_sha }}" in workflow
    assert "READONLY_RULES_SHA_MISMATCH" in workflow
    assert "actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea" in workflow
    assert "actions/github-script@v7" not in workflow
    assert "f6ccb143a581e28650e9b640226f9ef671d469f2" not in workflow
    assert "'origin/main'" in workflow


def test_runtime_canary_isolated_from_all_pr_events() -> None:
    """PR ready/synchronize/reopened must never queue a self-hosted canary."""
    workflow = (ROOT / ".github" / "workflows" / "runtime-canary.yml").read_text(
        encoding="utf-8"
    )
    trigger = workflow.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
    assert "pull_request:" not in trigger
    assert "pull_request_target:" not in trigger
    assert "push:" not in trigger
    assert "workflow_dispatch:" in trigger
    assert "schedule:" in trigger
    assert 'cron: "17 * * * *"' in trigger
    assert "ready_for_review" not in trigger

    gate = "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    assert workflow.count(gate) == 2  # physical job + its queue watchdog
    assert "if: github.event_name != 'pull_request'" not in workflow
    assert "name: Runner, Docker and workers canary" in workflow
    assert "name: Runtime canary queue watchdog" in workflow
    assert "SESSION_LAUNCH_OK" in workflow
    assert "--require-runner-version-preflight" in workflow
    assert "scripts\\command_gateway.py" in workflow
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in workflow
