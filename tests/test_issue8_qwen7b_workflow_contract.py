"""Source-level preventions for issue #8 one-time physical pipeline.

These are static and syntax gates. Only a real Actions run can prove execution.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FLOW = ROOT / ".github/workflows/issue8-qwen7b-fenced-bundle-dev.yml"


def workflow() -> str:
    return FLOW.read_text(encoding="utf8").replace("\r\n", "\n")


def scripts():
    lines = workflow().splitlines()
    chunks: list[str] = []
    for i, line in enumerate(lines):
        if line.strip() != "script: |":
            continue
        indent = len(line) - len(line.lstrip())
        body = []
        for item in lines[i + 1:]:
            if item.startswith(" " * (indent + 2)):
                body.append(item[indent + 2:])
            elif not item.strip():
                body.append("")
            else:
                break
        chunks.append("\n".join(body))
    return chunks


def test_all_embedded_github_scripts_parse_under_node_js():
    snippets = scripts()
    assert len(snippets) == 6
    for snippet in snippets:
        with tempfile.TemporaryDirectory(prefix="issue8-js-check-") as d:
            path = Path(d) / "source.cjs"
            path.write_text("async function github_script_contract() {\n" + snippet + "\n}\n", encoding="utf8")
            result = subprocess.run(
                ["node", "--check", str(path)],
                capture_output=True, text=True, timeout=20,
                check=False,
            )
            assert result.returncode == 0, result.stderr[:1000]


def test_same_owner_and_one_time_pr_admission():
    text = workflow()
    assert "types: [opened, synchronize, reopened, edited]" in text
    assert "github.actor == 'ericson-j-santos'" in text
    assert "github.event.pull_request.draft == true" in text
    assert "github.event.pull_request.head.repo.full_name == github.repository" in text
    assert "!contains(github.event.changes.body.from," in text
    assert "OWNER_ISSUE8_FENCED_BUNDLE_20261025_ONCE" in text
    assert "comment_id:6399359287" in text
    assert "ISSUE8_OWNER_OR_SOURCE_UNVERIFIED" in text
    assert "ISSUE8_REQUIRED_CI_NOT_EXECUTED" in text
    assert "cancel-in-progress: false" in text
    assert "21fd68dec6f0da92b3e7da201463401ac5429d64" in text


def test_gateway_and_worker_restrictions_are_retained():
    text = workflow()
    assert "DESKTOP-PDQK954-runtime" in text
    assert "runs-on: [self-hosted, Windows, X64, pc24x7," in text
    assert "--require-runner-version-preflight" in text
    assert "SESSION_LAUNCH_OK" in text
    assert "SESSION_STATE_VALIDATED: \"true\"" in text
    assert "--risk','2'" in text
    assert "shell: powershell" in text
    assert "shell: pwsh" not in text
    assert "GH_TOKEN: \"\"" in text and "GITHUB_TOKEN: \"\"" in text
    assert "Native Python venv through governed Gateway" in text
    assert "source='21fd68dec6f0da92b3e7da201463401ac5429d64'" in text
    assert "actions/upload-artifact" not in text
    assert "actions/download-artifact" not in text
    assert "300000" in text


def test_privileged_job_separate_from_model_and_validator():
    text = workflow()
    assert "\n  publish-cas:\n" in text
    parts = text.split("\n  publish-cas:\n")
    writer = parts[1].split("\n  validator:\n")[0]
    model = text.split("\n  physical:\n")[1].split("\n  publish-cas:\n")[0]
    assert "contents: write" in writer
    assert "actions/checkout" not in writer
    assert "github.rest.repos.createOrUpdateFileContents" in writer
    assert "contents: write" in writer and "contents: write" not in model
    assert "contents: read" in model
    assert "contents: write" not in model
    assert "OWNER_ISSUE8_FENCED_BUNDLE_20261025_ONCE" in writer
    assert "ISSUE8_CAS_INDEPENDENT_READBACK_MISSING" in writer
    assert "ISSUE8_VALIDATOR_CAS_READBACK_INVALID" in text
    assert '"ready_for_pr": False' in (ROOT /
        "scripts/issue8_qwen7b_independent_bundle_validator.py").read_text("utf8")
    for forbidden in ("docker run", "docker compose", "gh pr merge",
                      "git push", "ollama pull", "force-with-lease"):
        assert forbidden not in text.lower()


def test_only_one_file_and_sha_bound_output():
    text=workflow()
    assert re.search(r"diff\.ahead_by!==1.+diff\.behind_by!==0",text)
    assert "diff.total_commits!==1" in text
    assert "diff.files?.length!==1" in text
    assert "pr.head.sha!==context.payload.pull_request.head.sha" in text
    assert "gitBlob" in text
    assert "bundle_sha256" in text
    assert "produced_sha" in text


def test_quarantine_is_durable_but_cannot_promote_failed_physical_job():
    text = workflow()
    assert "\n  quarantine-cas:\n" in text
    assert "\n  quarantine-readback:\n" in text
    assert "always() && needs.physical.result == 'failure'" in text
    assert "needs.physical.outputs.bundle_b64 != ''" in text
    assert "ISSUE8_QUARANTINE_ATTESTATION_INVALID" in text
    assert "ISSUE8_QUARANTINE_READBACK_FAILED" in text
    assert "agent/issue8-qwen-quarantine-" in text
    assert "contents: write" in text.split("\n  quarantine-cas:\n")[1].split("\n  quarantine-readback:\n")[0]
    assert "contents: write" not in text.split("\n  quarantine-readback:\n")[1]
    assert "if: needs.publish-cas.result == 'success'" in text
    assert "if: needs.physical.result == 'success'" in text
    writer = text.split("\n  quarantine-cas:\n")[1].split("\n  quarantine-readback:\n")[0].lower()
    assert "ready_for_pr=false" in writer
    assert "ready_for_pr=true" not in writer
