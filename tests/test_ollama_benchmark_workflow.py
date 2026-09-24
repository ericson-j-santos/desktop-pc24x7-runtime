from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "ollama-local-benchmark-dev.yml"
)


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_benchmark_targets_only_dedicated_desktop_runner() -> None:
    content = workflow_text()
    assert (
        "runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev]"
        in content
    )
    assert "timeout-minutes: 8" in content
    assert (
        "github.event.pull_request.head.repo.full_name == github.repository"
        in content
    )


def test_benchmark_queue_is_bounded_by_canonical_watchdog() -> None:
    content = workflow_text()
    trigger_block = content.split("\npermissions:", 1)[0]

    assert "\n  push:" not in trigger_block
    assert "workflow_dispatch:" in trigger_block
    assert "pull_request:" in trigger_block
    assert "physical_runner_watchdog:" in content
    assert 'STALL_AFTER_SECONDS: "60"' in content
    assert "timeout-minutes: 2" in content
    assert "actions: write" in content
    assert "_rules/scripts/progress_watchdog.py" in content
    assert "cancelWorkflowRun" in content
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in content

# probe: dedicated broker recovery 2026-09-24
