"""Prevent activation of the retired source; no credentials or external services."""
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/todo-hosted-backup.yml"


def assert_source_retired(text: str) -> None:
    triggers = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert re.findall(r"^  ([a-z_]+):", triggers, re.M) == ["pull_request", "push"]
    job = text.split("\n  backup:\n", 1)[1]
    guards = re.findall(r"^    if:\s*(.+)$", job, re.M)
    assert len(guards) == 1
    assert guards[0].startswith("${{ false && (")
    assert guards[0].endswith(" }}")
    assert "NEON_RETIRED_20261019" in job
    checks = text.split("\n  synthetic_checks:\n", 1)[1].split("\n  backup:\n", 1)[0]
    assert "tests/test_todo_neon_retired.py" in checks
    assert "tests/test_todo_hosted_backup.py" in checks
    assert "contents: read" in checks
    assert "secrets." not in checks
    assert "environment:" not in checks
    assert "python3 scripts/todo_hosted_backup.py" not in checks


def test_retired_source_cannot_run():
    assert_source_retired(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize("before,after", [
    ("  # Source retired", '  schedule:\n    - cron: "27 4 * * *"\n  # Source retired'),
    ("  # Source retired", "  workflow_dispatch:\n  # Source retired"),
    ("  # Source retired", "  repository_dispatch:\n  # Source retired"),
    ("${{ false && (", "${{ true && ("),
    ("${{ false && (", "${{ ("),
    ("contents: read\n    steps:", "contents: write\n    steps:"),
    ("    name: Validate hosted runner backup safety offline", "    environment: todo-pg-backup\n    name: Validate hosted runner backup safety offline"),
])
def test_policy_detects_reactivation_and_privilege_mutations(before, after):
    source = WORKFLOW.read_text(encoding="utf-8")
    mutated = source.replace(before, after)
    assert mutated != source
    with pytest.raises(AssertionError):
        assert_source_retired(mutated)


def test_current_route_does_not_claim_migrated_history_or_running_service():
    doc = (ROOT / "docs/todo-without-neon.md").read_text(encoding="utf-8")
    for term in (
        "Notion", "SQLite", "PostgreSQL próprio", "histórico exclusivo",
        "não foi instalado", "sem Neon", "novo evento", "não executar",
    ):
        assert term.casefold() in doc.casefold()
