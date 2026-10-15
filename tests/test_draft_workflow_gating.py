from __future__ import annotations

from pathlib import Path

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
    "runtime-canary.yml": 1,
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


def test_drafts_keep_hosted_ci_without_physical_claim() -> None:
    content = workflow_text("ci.yml")
    assert "pull_request:" in content
    assert "runs-on: windows-latest" in content
