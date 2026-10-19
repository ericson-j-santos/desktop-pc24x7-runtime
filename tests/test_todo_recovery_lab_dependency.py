"""Keep the real PostgreSQL drill native, bounded and isolated from live services."""
from pathlib import Path
import re

import pytest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/todo-recovery-isolated-e2e.yml"


def assert_native_lab(text: str) -> None:
    assert "runs-on: ubuntu-24.04" in text
    assert not re.search(r"^\s*(?:container|services):", text, re.M)
    assert not re.search(r"^\s*-?\s*uses:\s*docker://", text, re.M)
    assert not re.search(r"^\s*(?:sudo\s+)?docker(?:\s|$)", text, re.M)
    assert "sudo -E" not in text and "--preserve-env" not in text

    python_install = "install -y --no-install-recommends python3"
    compile_command = "/usr/bin/python3 -m py_compile"
    pg_install = "install -y --no-install-recommends postgresql-18 postgresql-client-18"
    for required in (
        "Install Python and native lab dependencies",
        python_install, compile_command, pg_install,
        "python3-cryptography python3-pytest",
        "ca-certificates curl gosu",
        "https://apt.postgresql.org/pub/repos/apt",
        "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
        "Suites: noble-pgdg",
        "Signed-By: /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc",
        "create_main_cluster = false",
        "start_conf = manual",
        "'exit 101'",
        "/usr/sbin/policy-rc.d",
        "Dpkg::Options::=--force-confold",
        "/usr/lib/postgresql/18/bin/$tool",
        "Acquire::Retries=0",
        "timeout-minutes: 2",
        "timeout-minutes: 4",
    ):
        assert required in text, required
    assert text.index(python_install) < text.index(compile_command)
    assert text.index("create_main_cluster = false") < text.index(pg_install)
    assert text.index("'exit 101'") < text.index(python_install)
    assert text.index(pg_install) < text.index(compile_command)

    restore_steps = (
        ("Restore core and hosted captures, verify SQL, replay and reject invalid states",
         "TODO_RECOVERY_LAB", "tests/e2e_pc24x7_todo_recovery.py"),
        ("Restore the Notion snapshot in an independent native PostgreSQL 18 lab",
         "TODO_NOTION_LAB", "tests/e2e_todo_notion_backup.py"),
    )
    for name, guard, script in restore_steps:
        marker = f"      - name: {name}\n"
        assert marker in text
        step = text.split(marker, 1)[1].split("      - name:", 1)[0]
        assert "timeout-minutes: 3" in step
        assert "sudo env -i" in step
        assert guard + '=synthetic-only' in step
        assert 'GITHUB_ACTIONS="$GITHUB_ACTIONS"' in step
        assert 'GITHUB_SHA="$GITHUB_SHA"' in step
        assert f'/usr/bin/python3 "$GITHUB_WORKSPACE/{script}"' in step
    assert 'PYTHONPATH="$GITHUB_WORKSPACE/scripts"' in text
    assert re.findall(r"^\s+path:\s*(.+)$", text, re.M) == [
        "recovery-e2e-receipt.json",
        "todo-notion-recovery-e2e-receipt.json",
    ]


def test_lab_prepares_python_before_compilation():
    assert_native_lab(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize("before,after", [
    ("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
    ("    env:\n", "    container:\n      image: postgres:18\n    env:\n"),
    ("    env:\n", "    services:\n      pg:\n        image: postgres:18\n    env:\n"),
    ("    steps:\n", "    steps:\n      - uses: docker://postgres:18\n"),
    ("    steps:\n", "    steps:\n      - name: Added runtime\n        run: |\n          docker run postgres:18\n"),
    ("postgresql-18 postgresql-client-18", "postgresql-17 postgresql-client-17"),
    ("create_main_cluster = false", "create_main_cluster = true"),
    ("'exit 101'", "'exit 0'"),
    ("sudo env -i", "sudo -E env"),
    ('GITHUB_SHA="$GITHUB_SHA"', "GITHUB_SHA=not-forwarded"),
    ("path: recovery-e2e-receipt.json", "path: '**'"),
])
def test_native_lab_contract_rejects_runtime_and_boundary_regressions(before, after):
    original = WORKFLOW.read_text(encoding="utf-8")
    changed = original.replace(before, after)
    assert changed != original
    with pytest.raises(AssertionError):
        assert_native_lab(changed)
