"""Static gate: probe cannot enter the Qwen repair lane or bypass Gateway."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/issue8-sandbox-residual-probe.yml"


def test_one_shot_owner_and_sha_guard_and_no_model_job():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "OWNER_ISSUE8_READONLY_PROBE_20261025_ONCE" in text
    assert "!contains(github.event.changes.body.from" in text
    assert "github.actor == 'ericson-j-santos'" in text
    assert "needs.admission.result == 'success'" in text
    assert "source_sha=" not in text
    assert "compareCommitsWithBasehead" in text
    assert "lineage.data.behind_by===0" in text
    assert "reviewedFile.data.sha==='d9a25c574163c49f695e774609949160d94f4490'" in text
    assert "worker.data.commit.sha!=='21fd68dec6f0da92b3e7da201463401ac5429d64'" not in text
    assert "40214413825" in text
    assert "SESSION_LAUNCH_OK" in text
    assert "--require-runner-version-preflight" in text
    assert "--risk','1'" in text
    assert "scripts\\issue8_sandbox_residual_probe.py" in text
    assert "contents: write" not in text
    assert "ollama run" not in text.lower()
    assert "native Python venv" not in text
    assert "createOrUpdateFileContents" not in text
