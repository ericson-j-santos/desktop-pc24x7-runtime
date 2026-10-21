"""Policy regression checks for execution boundaries, with weakened-policy negatives."""
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/todo-notion-backup.yml"

EXPECTED_GUARD = (
    "github.repository == 'ericson-j-santos/desktop-pc24x7-runtime' && "
    "github.ref == 'refs/heads/main' && "
    "(github.event_name == 'push' || "
    "github.event_name == 'workflow_dispatch' || "
    "(github.event_name == 'schedule' && vars.TODO_NOTION_SCHEDULE_ENABLED == 'true'))"
)


def enforce_policy(text):
    assert "\npermissions:\n  contents: read\n" in text
    assert "\n  safety:\n" in text and "\n  backup:\n" in text
    safety, backup = text.split("\n  safety:\n", 1)[1].split("\n  backup:\n", 1)
    assert "secrets." not in safety and "environment:" not in safety
    assert "contents: write" not in safety and "github.token" not in safety
    assert "needs: safety" in backup
    guard = re.search(r"    if: >-\n(.*?)    runs-on:", backup, re.S)
    assert guard and " ".join(guard[1].split()) == EXPECTED_GUARD
    assert "    environment: todo-notion-backup\n" in backup
    assert "    permissions:\n      contents: write\n" in backup
    assert text.count("runs-on: ubuntu-24.04") == 2
    assert not re.search(r"(?im)^\s*(container|services):", text)
    assert "self-hosted" not in "\n".join(line for line in text.splitlines()
                                         if not line.lstrip().startswith("#"))
    assert "upload-artifact@" not in text and "actions/cache@" not in text
    assert "TODO_RECOVERY_IDENTITY_FILE" not in text and "PRIVATE_KEY" not in text
    assert text.count("persist-credentials: false") == 2
    assert "python scripts/todo_notion_hosted_backup.py" in backup
    assert "TODO_NOTION_READ_TOKEN: ${{ secrets.TODO_NOTION_READ_TOKEN }}" in backup
    assert "TODO_BACKUP_CUSTODY_APPROVAL: ${{ vars.TODO_BACKUP_CUSTODY_APPROVAL }}" in backup
    for suite in ("snapshot", "sealed", "hosted_backup", "restore", "workflow"):
        assert "tests/test_todo_notion_" + suite + ".py" in safety
    assert "tests/test_todo_neon_retired.py" in safety
    assert "cancel-in-progress: false" in text


def test_current_workflow_policy():
    enforce_policy(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize("old,new", [
    ("github.ref == 'refs/heads/main'", "true"),
    ("needs: safety", "needs: []"),
    ("vars.TODO_NOTION_SCHEDULE_ENABLED == 'true'", "true"),
    ("environment: todo-notion-backup", "environment: other"),
    ("github.event_name == 'push'", "github.event_name == 'pull_request'"),
    ("github.event_name == 'workflow_dispatch'", "github.event_name == 'pull_request'"),
    ("contents: read", "contents: write"),
    ("persist-credentials: false", "persist-credentials: true"),
    ("runs-on: ubuntu-24.04", "runs-on: self-hosted"),
])
def test_weakened_workflow_is_rejected(old, new):
    original = WORKFLOW.read_text(encoding="utf-8")
    assert old in original
    with pytest.raises(AssertionError):
        enforce_policy(original.replace(old, new, 1))


def test_neon_capture_remains_retired():
    legacy = (ROOT / ".github/workflows/todo-hosted-backup.yml").read_text(encoding="utf-8")
    assert "NEON_RETIRED_20261019" in legacy
    assert "false &&" in legacy
    trigger = legacy.split("\njobs:", 1)[0]
    assert not re.search(r"(?m)^  (schedule|workflow_dispatch):", trigger)


def test_native_notional_e2e_is_in_required_recovery_workflow():
    native = (ROOT / ".github/workflows/todo-recovery-isolated-e2e.yml").read_text(encoding="utf-8")
    assert "tests/e2e_todo_notion_backup.py" in native
    assert "TODO_NOTION_LAB=synthetic-only" in native
    assert "todo-notion-recovery-e2e-receipt.json" in native
    assert not re.search(r"(?im)^\s*(container|services):", native)
    assert not re.search(r"(?im)^\s*(?:-\s*)?run:.*\b(?:docker|podman)\b", native)
