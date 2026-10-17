"""Prevent a database-only container from being treated as a Python executor."""
from pathlib import Path


def test_lab_prepares_python_before_compilation():
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/todo-recovery-isolated-e2e.yml"
    text = workflow.read_text(encoding="utf-8")
    assert "Install Python in the disposable lab container" in text
    assert text.index("install -y --no-install-recommends python3") < text.index("python3 -m py_compile")
    assert "Acquire::Retries=0" in text
    assert "timeout-minutes: 2" in text
