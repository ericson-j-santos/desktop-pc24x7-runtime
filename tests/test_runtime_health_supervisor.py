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
    assert 'runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev]' in workflow
    assert "--require-runner-version-preflight" in workflow
    assert "steps.session.outputs.target_path" in workflow
    assert "scripts\\command_gateway.py" in workflow
    assert "schedule:" in workflow
    assert "pull_request:" in workflow
    assert "github.event.pull_request.head.sha || github.sha" in workflow
