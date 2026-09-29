from __future__ import annotations

from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "dedicated-runtime-runner-e2e.yml"
)


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_canary_is_manual_and_gated_by_canonical_rules() -> None:
    raw = workflow_text()
    trigger_block = raw.split("\npermissions:", 1)[0]
    assert "workflow_dispatch:" in trigger_block
    assert "\n  push:" not in trigger_block
    assert "Resolve main SHA and require rules 1.6.9+" in raw
    assert "RULES_1_6_9_REQUIRED" in raw
    assert "chatgpt-operational-rules" in raw


def test_canary_bootstraps_before_gateway_execution() -> None:
    raw = workflow_text()
    bootstrap = raw.index("Bootstrap governed session and runner version preflight")
    gateway = raw.index("Prove exact host, repository, runner and version through Command Gateway")
    assert bootstrap < gateway
    assert "--require-runner-version-preflight" in raw
    assert "SESSION_LAUNCH_OK" in raw
    assert "RUNNER_VERSION_PREFLIGHT_BLOCKED" in raw
    assert "command_gateway.py" in raw
    assert "scripts\\dedicated_runner_e2e.py" in raw


def test_canary_persists_runner_version_contract() -> None:
    raw = workflow_text()
    assert "RUNNER_VERSION_OBSERVED" in raw
    assert "RUNNER_REGISTRATION_SUPPORTED" in raw
    assert "RUNNER_RUNTIME_SUPPORTED" in raw
    assert "RUNNER_DEPRECATION_API_STATUS" in raw


def test_canary_queue_is_bounded_fail_closed() -> None:
    raw = workflow_text()
    assert "name: Dedicated runner queue watchdog" in raw
    assert 'STALL_AFTER_SECONDS: "60"' in raw
    assert "progress_watchdog.py" in raw
    assert "actions: write" in raw
    assert "cancelWorkflowRun" in raw
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in raw
