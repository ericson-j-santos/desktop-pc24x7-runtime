"""Negative and positive admission tests for owner-only Desktop recovery readback.

The tested scripts run on public hosted GitHub runners; this fixture never calls
the physical host, creates a GitHub artifact, or installs a runtime.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = "86abe65b22781c2f608a7d7286ce3a28cd48aaaf"
MAIN = "a" * 40
WORKFLOWS = [
    (
        ".github/workflows/desktop-orchestrator-isolated-rollback.yml",
        "VERIFY-DESKTOP-ORCHESTRATOR-ISOLATED-ROLLBACK-DEV",
        "fix/desktop-orchestrator-isolated-rollback-20261012",
    ),
    (
        ".github/workflows/desktop-orchestrator-protected-state.yml",
        "VERIFY-DESKTOP-ORCHESTRATOR-PROTECTED-STATE-DEV",
        "fix/desktop-orchestrator-protected-state-20261012",
    ),
]

# Run the actual actions/github-script admission JavaScript with bounded mocks.
NODE = r"""
const fs = require('node:fs');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const p = JSON.parse(fs.readFileSync(0, 'utf8'));
const sha = p.sha ?? p.main;
const context = {
  eventName: p.event ?? 'workflow_dispatch',
  actor: p.actor ?? 'ericson-j-santos',
  repo: { owner: p.owner ?? 'ericson-j-santos',
          repo: p.repo ?? 'desktop-pc24x7-runtime' },
  ref: p.ref ?? 'refs/heads/main',
  sha,
  payload: { inputs: {
    action: p.action ?? p.scope,
    expected_head_sha: p.expected_head_sha ?? p.main,
    expected_rules_sha: p.expected_rules_sha ?? p.rules
  } }
};
const github = { rest: { repos: {
  get: async () => ({ data: { private: p.private ?? false } }),
  getBranch: async ({repo}) => ({data: { commit: {
    sha: repo === 'chatgpt-operational-rules'
      ? (p.rules_head ?? p.rules)
      : (p.main_head ?? p.main)
  } } })
} } };
(async () => {
  try {
    await new AsyncFunction('context', 'github', p.script)(context, github);
    process.stdout.write('ADMITTED');
  } catch (error) {
    process.stdout.write(String(error.message || error));
    process.exitCode = 7;
  }
})();
"""


def load(path: str) -> dict:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def run_admission(script: str, scope: str, **overrides) -> tuple[int, str]:
    payload = dict(script=script, scope=scope, main=MAIN, rules=RULES)
    payload.update(overrides)
    result = subprocess.run(
        ["node", "-e", NODE],
        input=json.dumps(payload), capture_output=True, text=True, timeout=10,
        check=False,
    )
    return result.returncode, result.stdout


@pytest.mark.parametrize("path,scope,legacy", WORKFLOWS)
def test_manual_dispatch_is_fixed_to_public_owner_and_readback(path, scope, legacy):
    doc = load(path)
    events = doc.get("on", doc.get(True))  # PyYAML 1.1 recognizes 'on' as bool.
    assert list(events["workflow_dispatch"]["inputs"]["action"]["options"]) == [scope]
    assert events["workflow_dispatch"]["inputs"]["expected_head_sha"]["required"] is True
    assert events["workflow_dispatch"]["inputs"]["expected_rules_sha"]["required"] is True
    assert events["push"]["branches"] == [legacy]
    jobs = doc["jobs"]
    assert jobs["physical_backup" if "isolated" in path else "physical_state"]["needs"] == "contract"
    assert "RECOVERY_OWNER_MAIN_SCOPE_DENIED" in jobs["contract"]["steps"][0]["with"]["script"]
    physical = jobs["physical_backup" if "isolated" in path else "physical_state"]
    serialized = json.dumps(physical)
    assert "SESSION_LAUNCH_OK" in serialized
    assert "state_validated" in serialized
    assert "command_gateway.py" in serialized
    assert "'--risk', '2'" in serialized
    assert "origin/main" in serialized
    assert "ref: " + RULES in (ROOT / path).read_text(encoding="utf-8")
    uploads = [x for x in physical["steps"] if "upload-artifact" in x.get("uses", "")]
    assert len(uploads) == 1
    assert "github.event_name != 'workflow_dispatch'" in uploads[0]["if"]
    assert "Docker" not in serialized


@pytest.mark.parametrize("path,scope,legacy", WORKFLOWS)
def test_admission_positive_and_legacy_path(path, scope, legacy):
    script = load(path)["jobs"]["contract"]["steps"][0]["with"]["script"]
    assert run_admission(script, scope) == (0, "ADMITTED")
    assert run_admission(script, scope, event="push", ref="refs/heads/" + legacy) == (0, "ADMITTED")


NEGATIVE = [
    ({"actor": "untrusted-user"}, "RECOVERY_OWNER_MAIN_SCOPE_DENIED"),
    ({"owner": "other-owner"}, "RECOVERY_OWNER_MAIN_SCOPE_DENIED"),
    ({"repo": "other-repo"}, "RECOVERY_OWNER_MAIN_SCOPE_DENIED"),
    ({"ref": "refs/heads/feature"}, "RECOVERY_OWNER_MAIN_SCOPE_DENIED"),
    ({"action": "INSTALL-LIVE"}, "RECOVERY_OWNER_MAIN_SCOPE_DENIED"),
    ({"sha": "b" * 40}, "RECOVERY_EXPECTED_SHA_INVALID"),
    ({"expected_head_sha": "not-a-sha"}, "RECOVERY_EXPECTED_SHA_INVALID"),
    ({"expected_rules_sha": "not-a-sha"}, "RECOVERY_EXPECTED_SHA_INVALID"),
    ({"private": True}, "RECOVERY_COST_PUBLIC_REQUIRED"),
    ({"main_head": "b" * 40}, "RECOVERY_MAIN_MOVED"),
    ({"rules_head": "b" * 40}, "RECOVERY_RULES_SHA_MOVED"),
    ({"expected_rules_sha": "b" * 40}, "RECOVERY_RULES_SHA_MOVED"),
    ({"event": "push", "ref": "refs/heads/main"}, "RECOVERY_EVENT_NOT_ADMITTED"),
    ({"event": "pull_request"}, "RECOVERY_EVENT_NOT_ADMITTED"),
]


@pytest.mark.parametrize("path,scope,legacy", WORKFLOWS)
@pytest.mark.parametrize("override,blocked", NEGATIVE)
def test_admission_rejects_invalid_owner_sha_scope_cost_and_event(path, scope, legacy, override, blocked):
    script = load(path)["jobs"]["contract"]["steps"][0]["with"]["script"]
    code, observed = run_admission(script, scope, **override)
    assert code == 7, observed
    assert observed == blocked
