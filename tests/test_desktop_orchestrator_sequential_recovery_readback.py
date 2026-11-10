"""Owner-only admission and structural regression tests for sequential DEV restore.

These tests never dispatch a workflow, touch the Desktop or upload evidence.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/desktop-orchestrator-sequential-recovery-readback.yml"
MAIN = "a" * 40
RULES = "86abe65b22781c2f608a7d7286ce3a28cd48aaaf"

NODE = r"""
const fs = require('node:fs');
const p = JSON.parse(fs.readFileSync(0, 'utf8'));
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const context = {
  eventName: p.event ?? 'workflow_dispatch',
  actor: p.actor ?? 'ericson-j-santos',
  repo: { owner: p.owner ?? 'ericson-j-santos',
          repo: p.repo ?? 'desktop-pc24x7-runtime' },
  ref: p.ref ?? 'refs/heads/main',
  sha: p.sha ?? p.main,
  payload: {inputs: {
    expected_head_sha: p.expected_head_sha ?? p.main,
    expected_rules_sha: p.expected_rules_sha ?? p.rules,
    action: p.action ?? 'VERIFY-DESKTOP-RECOVERY-SEQUENTIAL-DEV'
  }}
};
const github = { rest: { repos: {
  get: async () => ({data: {private: p.private ?? false}}),
  getBranch: async ({repo}) => ({data: {commit: {sha:
    repo === 'chatgpt-operational-rules' ? (p.rules_head ?? p.rules)
      : (p.main_head ?? p.main)
  }}})
} }};
const core = {setOutput: (key, value) => {
  if (key !== 'rules_sha' || value !== p.rules) throw new Error('BAD_OUTPUT');
}};
(async () => {
  try {
    await new AsyncFunction('context', 'github', 'core', p.script)(context, github, core);
    process.stdout.write('ADMITTED');
  } catch (error) {
    process.stdout.write(String(error.message || error));
    process.exitCode = 7;
  }
})();
"""


def ler() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def executar_porteiro(**extras) -> tuple[int, str]:
    script = ler()["jobs"]["admission"]["steps"][0]["with"]["script"]
    payload = dict(script=script, main=MAIN, rules=RULES)
    payload.update(extras)
    run = subprocess.run(
        ["node", "-e", NODE], input=json.dumps(payload),
        capture_output=True, text=True, timeout=10, check=False,
    )
    return run.returncode, run.stdout


def test_acao_proprietario_main_publica_passou():
    assert executar_porteiro() == (0, "ADMITTED")


@pytest.mark.parametrize("alteracao,erro", [
    ({"event": "push"}, "SEQUENTIAL_OWNER_MAIN_SCOPE_DENIED"),
    ({"event": "issue_comment"}, "SEQUENTIAL_OWNER_MAIN_SCOPE_DENIED"),
    ({"actor": "outro"}, "SEQUENTIAL_OWNER_MAIN_SCOPE_DENIED"),
    ({"owner": "outro"}, "SEQUENTIAL_OWNER_MAIN_SCOPE_DENIED"),
    ({"repo": "outro"}, "SEQUENTIAL_OWNER_MAIN_SCOPE_DENIED"),
    ({"ref": "refs/heads/feature"}, "SEQUENTIAL_OWNER_MAIN_SCOPE_DENIED"),
    ({"action": "INSTALL-RUNTIME"}, "SEQUENTIAL_OWNER_MAIN_SCOPE_DENIED"),
    ({"sha": "b" * 40}, "SEQUENTIAL_EXPECTED_SHA_INVALID"),
    ({"expected_head_sha": "invalido"}, "SEQUENTIAL_EXPECTED_SHA_INVALID"),
    ({"expected_rules_sha": "invalido"}, "SEQUENTIAL_EXPECTED_SHA_INVALID"),
    ({"private": True}, "SEQUENTIAL_COST_PUBLIC_REQUIRED"),
    ({"main_head": "b" * 40}, "SEQUENTIAL_MAIN_MOVED"),
    ({"rules_head": "b" * 40}, "SEQUENTIAL_RULES_SHA_MOVED"),
    ({"expected_rules_sha": "b" * 40}, "SEQUENTIAL_RULES_SHA_MOVED"),
])
def test_porteiro_rejeita_entradas_indevidas(alteracao, erro):
    status, retorno = executar_porteiro(**alteracao)
    assert status == 7
    assert retorno == erro


def test_esquema_controles_positivos_e_custo_zero():
    doc = ler()
    events = doc.get("on", doc.get(True))  # YAML 1.1 transforma "on" em True.
    assert set(events) == {"workflow_dispatch"}
    assert doc["permissions"] == {"contents": "read"}
    assert doc["concurrency"]["cancel-in-progress"] is False
    entrada = events["workflow_dispatch"]["inputs"]
    assert set(entrada["action"]["options"]) == {
        "VERIFY-DESKTOP-RECOVERY-SEQUENTIAL-DEV"}
    assert entrada["expected_head_sha"]["required"]
    assert entrada["expected_rules_sha"]["required"]
    assert doc["jobs"]["admission"]["runs-on"] == "ubuntu-latest"
    physical = doc["jobs"]["physical"]
    assert physical["needs"] == "admission"
    assert physical["runs-on"] == [
        "self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime",
        "runtime-dev", "desktop-pdqk954",
    ]
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "SEQUENTIAL_COST_PUBLIC_REQUIRED" in text
    assert "SESSION_LAUNCH_OK" in text and "state_validated" in text
    assert "--require-runner-version-preflight" in text
    assert "--sync-ref', 'origin/main'" in text
    assert "command_gateway.py" in text
    assert "'--risk', '2'" in text
    assert "SEQUENTIAL_RECOVERY_READBACK_VERIFIED" in text
    assert "upload-artifact" not in text
    assert "docker " not in text.lower()


def test_probes_em_ordem_sem_bypass_e_sem_recuperar_servico_vivo():
    doc = ler()
    steps = doc["jobs"]["physical"]["steps"]
    assert len(steps) == 4
    assert steps[2]["id"] == "session"
    runner = steps[3]["run"]
    isolated = runner.index("$isolated = Invoke-ApprovedProbe ")
    first = runner.index("$first = Invoke-ApprovedProbe ")
    second = runner.index("$second = Invoke-ApprovedProbe ")
    shadow = runner.index("$shadow = Invoke-ApprovedProbe ")
    assert isolated < first < second < shadow
    assert "SEQUENTIAL_ISOLATED_RESTORE_REJECTED" in runner
    assert "SEQUENTIAL_PROTECTED_STATE_REJECTED" in runner
    assert "SEQUENTIAL_REPLAY_REJECTED" in runner
    assert "SEQUENTIAL_SHADOW_REJECTED" in runner
    assert "source_sha -ne $env:GITHUB_SHA" in runner
    assert "recovery_allowed -ne $false" in runner
    assert "production_touched -ne $false" in runner
    assert "live_service_restarted -ne $false" in runner
    assert "worker_started -ne $false" in runner
    assert "snapshot_manifest_sha256 -ne $second.snapshot_manifest_sha256" in runner
