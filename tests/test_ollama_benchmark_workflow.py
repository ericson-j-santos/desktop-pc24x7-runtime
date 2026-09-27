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


def test_benchmark_requires_agentic_context_gate() -> None:
    content = workflow_text()
    assert 'MIN_CONTEXT: "64000"' in content
    assert '"--min-context", $env:MIN_CONTEXT' in content


def test_benchmark_uses_current_canonical_operational_rules() -> None:
    content = workflow_text()
    assert "881d9ca2f8e77025edb7298b22981109c567a730" in content
    assert "5af7b5ab6e31c24744176abd774855168c55953f" not in content
