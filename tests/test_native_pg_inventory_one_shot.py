from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "native-pg-inventory-one-shot.yml"
)


def test_one_shot_dispatcher_is_exact_main_ci_gated_and_fixed_scope():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_run:" in raw
    assert "workflows: [CI]" in raw
    assert "types: [completed]" in raw
    assert "branches: [main]" in raw
    assert "github.event.workflow_run.event == 'push'" in raw
    assert "github.event.workflow_run.conclusion == 'success'" in raw
    assert "github.event.workflow_run.head_branch == 'main'" in raw
    assert "github.event.workflow_run.actor.login == 'ericson-j-santos'" in raw
    assert "[native-pg-inventory-once:20261024-pdqk954]" in raw
    assert "branch.commit.sha !== headSha" in raw
    assert "workflow_id: 'dedicated-runtime-runner-e2e.yml'" in raw
    assert "diagnostic: 'native-postgres-inventory'" in raw
    assert "inventory_source_sha: headSha" in raw
    assert "inventory_dispatch_provenance: 'one-shot:20261024-pdqk954'" in raw


def test_one_shot_dispatcher_is_bounded_and_duplicate_safe():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "actions: write" in raw
    assert "contents: read" in raw
    assert "timeout-minutes: 2" in raw
    assert "cancel-in-progress: false" in raw
    assert "listWorkflowRuns" in raw
    assert "run.head_sha === headSha" in raw
    assert "ONE_SHOT_ALREADY_DISPATCHED" in raw
    assert "createWorkflowDispatch" in raw
    for forbidden in (
        "secrets.",
        "self-hosted",
        "powershell",
        "pwsh",
        "cmd.exe",
        "DATABASE_URL",
        "postgresql://",
    ):
        assert forbidden not in raw
