"""Regression gate for one-shot owner-approved Dell CAS physical workflow."""
from __future__ import annotations

from pathlib import Path

FLOW = (
    Path(__file__).resolve().parents[1]
    / ".github" / "workflows" / "issue-qwen7b-cas-physical-dev.yml"
)


def test_one_shot_owner_draft_admission_and_sha_gate():
    text = FLOW.read_text(encoding="utf-8")
    assert "types: [edited]" in text
    assert "github.actor == 'ericson-j-santos'" in text
    assert "github.event.pull_request.draft == true" in text
    assert "github.event.pull_request.head.repo.full_name == github.repository" in text
    assert "!contains(github.event.changes.body.from, 'OWNER_ISSUE_CAS_20261025_ONCE')" in text
    assert "wp.data.head.sha !== worker" in text
    assert "wmain.data.commit.sha !== base" in text
    assert "ISSUE_CAS_REQUIRED_CI" in text
    assert "ISSUE_CAS_OWNER_OR_WORKER_DRIFT" in text
    assert "WORKER_POOL_SHA: 00292e42c497c03bcda0dcb80750841a962c02c8" in text
    assert "OWNER_ISSUE_CAS_20261025_ONCE" in text


def test_physical_job_is_governed_and_never_uses_docker_or_unsafe_fallback():
    text = FLOW.read_text(encoding="utf-8")
    assert "DESKTOP-PDQK954" in text
    assert "desktop-runtime, runtime-dev, desktop-pdqk954" in text
    assert "--require-runner-version-preflight" in text
    assert "SESSION_LAUNCH_OK" in text
    assert "state_validated" in text
    assert "_rules\\scripts\\command_gateway.py" in text
    assert "'--session-id',$env:SESSION" in text
    assert "'--risk','2'" in text
    assert "issue_qwen7b_cas_physical_preflight.py" in text
    assert "EXPECTED_WORKER_SHA" in text and "EXPECTED_RUNTIME_SHA" in text
    assert "persist-credentials: false" in text
    assert "OWNER_ISSUE_CAS_20261025_ONCE" in text
    assert "cancelWorkflowRun" in text
    assert "300000" in text
    for disallowed in ("docker run", "docker compose", "git push",
                       "reset --hard", "force-with-lease", "enable_auto_merge",
                       "ollama pull", "gh pr merge"):
        assert disallowed not in text.lower()


def test_no_broad_workflow_write_permissions_or_secrets_inline():
    text = FLOW.read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in text
    assert "actions: write" in text  # Only a watchdog cancellation capability.
    assert "NATIVE_OLLAMA_DEV" in text
    assert "NATIVE_MODEL_DIGEST_PREFIX" in text
    assert "PORTFOLIO_GITHUB_TOKEN_FILE" not in text
    assert "PRIVATE_KEY" not in text
    assert "secrets." not in text
