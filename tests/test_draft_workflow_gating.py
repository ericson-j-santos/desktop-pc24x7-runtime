from __future__ import annotations

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

PHYSICAL_GATE = (
    "    if: github.event_name != 'pull_request' || "
    "(!github.event.pull_request.draft && "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)
PR_TYPES = "types: [opened, synchronize, reopened, ready_for_review]"

PHYSICAL_WORKFLOWS = {
    "runtime-canary.yml": 2,
    "engineering-worker-pool-smoke-dev.yml": 3,
    "ollama-local-benchmark-dev.yml": 2,
    "portfolio-bridge-preflight-dev.yml": 4,
}


def workflow_text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def physical_job_allowed(event_name: str, draft: bool, same_repository: bool) -> bool:
    """Model the workflow if-expression; drafts are never physical validation."""
    return event_name != "pull_request" or (not draft and same_repository)


@pytest.mark.parametrize("workflow,gate_count", PHYSICAL_WORKFLOWS.items())
def test_physical_workflows_gate_drafts_and_forks(workflow: str, gate_count: int) -> None:
    content = workflow_text(workflow)
    assert PR_TYPES in content
    assert content.count(PHYSICAL_GATE) == gate_count


@pytest.mark.parametrize(
    ("event_name", "draft", "same_repository", "allowed"),
    [
        ("pull_request", True, True, False),
        ("pull_request", False, True, True),
        ("pull_request", True, False, False),
        ("pull_request", False, False, False),
        ("push", False, False, True),
        ("schedule", False, False, True),
        ("workflow_dispatch", False, False, True),
    ],
)
def test_physical_gate_matrix(
    event_name: str, draft: bool, same_repository: bool, allowed: bool
) -> None:
    assert physical_job_allowed(event_name, draft, same_repository) is allowed


def test_ready_transition_is_explicit_and_dependencies_remain() -> None:
    engineering = workflow_text("engineering-worker-pool-smoke-dev.yml")
    portfolio = workflow_text("portfolio-bridge-preflight-dev.yml")
    assert "needs: prepare_runner" in engineering
    assert "needs: prepare_runner" in portfolio
    assert "ready_for_review" in engineering
    assert "ready_for_review" in portfolio


def test_rdc_recovery_job_keeps_nested_runs_on_and_manual_trigger() -> None:
    content = workflow_text("desktop-rdc-recovery.yml")
    assert "on:\n  workflow_dispatch:\n" in content
    assert (
        "  recover:\n"
        "    name: Recover RDC on PC24x7 Desktop\n"
        "    runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, desktop-pdqk954]"
        in content
    )


def assert_hosted_ci_matrix(content: str) -> None:
    assert re.search(r"^  pull_request:\s*$", content, re.M)
    assert re.search(r"^    runs-on: \$\{\{ matrix\.os \}\}\s*$", content, re.M)
    assert re.findall(r"^          - os: (\S+)\s*$", content, re.M) == [
        "windows-latest", "ubuntu-latest"
    ]
    assert "self-hosted" not in content
    assert not re.search(r"^\s+(needs|if):", content, re.M)


def test_drafts_keep_hosted_ci_without_physical_claim() -> None:
    assert_hosted_ci_matrix(workflow_text("ci.yml"))


@pytest.mark.parametrize("old,new", [
    ("- os: windows-latest", "- os: self-hosted"),
    ("- os: ubuntu-latest", "- os: windows-latest"),
    ("    timeout-minutes: 10", "    if: false\n    timeout-minutes: 10"),
])
def test_hosted_matrix_rejects_affinity_missing_os_and_suppression(old, new) -> None:
    content = workflow_text("ci.yml")
    assert_hosted_ci_matrix(content)
    assert old in content
    with pytest.raises(AssertionError):
        assert_hosted_ci_matrix(content.replace(old, new, 1))


# Workflow-level concurrency is acquired before a physical job can be skipped.
# Keep the existing host lock, but acquire it only for admitted physical jobs.
CANARY_JOB_LOCK = (
    "    concurrency:\n"
    "      group: pc24x7-runtime-canary-${{ github.event.number || github.ref_name }}\n"
    "      cancel-in-progress: false\n"
)


def assert_canary_lock_scope(content: str) -> None:
    header, jobs = content.split("\njobs:\n", 1)
    assert "\nconcurrency:" not in header, "drafts must not enter the host queue"
    assert jobs.startswith("  canary:\n")
    assert PHYSICAL_GATE in jobs, "physical admission must remain fail-closed"
    assert CANARY_JOB_LOCK in jobs, "admitted jobs must keep the existing host lock"
    assert jobs.index(PHYSICAL_GATE) < jobs.index(CANARY_JOB_LOCK)
    assert content.count("group: pc24x7-runtime-canary") == 1


def test_canary_skips_drafts_before_acquiring_host_lock() -> None:
    assert_canary_lock_scope(workflow_text("runtime-canary.yml"))


def test_canary_preserves_serialization_without_cancelling_active_jobs() -> None:
    content = workflow_text("runtime-canary.yml")
    assert CANARY_JOB_LOCK in content
    assert "cancel-in-progress: true" not in content
    assert "  contents: read" in content
    assert "actions: write" in content
    canary = content.split("  canary:\\n", 1)[1].split("\\n  queue_watchdog:", 1)[0]
    assert "actions: write" not in canary
    assert "    timeout-minutes: 4" in content
    assert "  schedule:\n    - cron: \"*/5 * * * *\"" in content
    assert "  workflow_dispatch:" in content


@pytest.mark.parametrize("fault", ["global-lock", "no-lock", "renamed-lock", "no-gate"])
def test_canary_lock_guard_rejects_regressions(fault: str) -> None:
    content = workflow_text("runtime-canary.yml")
    if fault == "global-lock":
        content = content.replace(
            "\npermissions:",
            "\nconcurrency:\n  group: pc24x7-runtime-canary\n\npermissions:",
            1,
        )
    elif fault == "no-lock":
        content = content.replace(CANARY_JOB_LOCK, "", 1)
    elif fault == "renamed-lock":
        content = content.replace("group: pc24x7-runtime-canary", "group: unshared", 1)
    else:
        content = content.replace(PHYSICAL_GATE, "    if: true", 1)
    with pytest.raises(AssertionError):
        assert_canary_lock_scope(content)
