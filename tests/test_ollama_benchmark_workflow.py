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


def test_benchmark_executes_context_ladder_and_repetition_gate() -> None:
    content = workflow_text()
    assert 'CONTEXTS: "8192,32768,64000"' in content
    assert 'REPETITIONS: "3"' in content
    assert '"--contexts", $env:CONTEXTS' in content
    assert '"--repetitions", $env:REPETITIONS' in content


def test_benchmark_uses_current_canonical_operational_rules() -> None:
    content = workflow_text()
    assert "10d2489e8cac3770d1c07fac4ccfece0a0112269" in content
    assert "881d9ca2f8e77025edb7298b22981109c567a730" not in content


def test_benchmark_watchdog_uses_current_attempt_clock() -> None:
    content = workflow_text()
    assert "const progressAnchor = new Date();" in content
    assert "runResponse.data.created_at" not in content
