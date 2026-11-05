"""Positive, negative, replay and no-network-fallback tests for CPU-first pilot."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ollama_cpu_pilot.py"
WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ollama-cpu-pilot-dev.yml"
DIGEST = "a" * 64


def module():
    spec = importlib.util.spec_from_file_location("ollama_cpu_pilot", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def weights():
    return {"models": [{
        "name": "qwen2.5-coder:7b", "size": 4_500_000_000,
        "digest": DIGEST, "details": {"format": "gguf"},
    }]}


def generation():
    return {
        "model": "qwen2.5-coder:7b", "done": True,
        "response": json.dumps({"sentinel": "OLLAMA_CPU_PILOT_OK"}),
        "eval_count": 8, "eval_duration": 2_000_000_000,
    }


def loaded():
    return {"models": [{
        "name": "qwen2.5-coder:7b", "digest": DIGEST,
        "context_length": 2048, "size_vram": 0,
    }]}


def run(mod, capsys, mode="inventory"):
    code = mod.main(["--mode", mode, "--correlation-id", "cpu-pilot-test-1"])
    return code, json.loads(capsys.readouterr().out)


def test_inventory_is_read_only_and_idempotent(monkeypatch, capsys):
    mod = module()
    calls = []

    def fake_http(path, **kwargs):
        calls.append(path)
        assert kwargs.get("payload") is None
        return weights()

    monkeypatch.setattr(mod, "http_json", fake_http)
    first, first_json = run(mod, capsys)
    second, second_json = run(mod, capsys)
    assert first == second == 0
    assert first_json == second_json
    assert first_json["state"] == "installed_weights_verified_inference_not_tested"
    assert first_json["model_pull_performed"] is False
    assert calls == ["/api/tags", "/api/tags"]


def test_missing_model_fails_without_downloading(monkeypatch, capsys):
    mod = module()
    seen = []

    def fake_http(path, **kwargs):
        seen.append(path)
        return {"models": []}

    monkeypatch.setattr(mod, "http_json", fake_http)
    code, evidence = run(mod, capsys)
    assert code == 2
    assert evidence["state"] == "model_not_installed"
    assert evidence["ok"] is False
    assert seen == ["/api/tags"]


@pytest.mark.parametrize(
    "broken",
    [
        {"size": 0},
        {"digest": "wrong"},
        {"details": {"format": "unknown"}},
        {"size": True},
    ],
)
def test_invalid_local_weights_fail_closed(monkeypatch, capsys, broken):
    mod = module()
    data = weights()
    data["models"][0].update(broken)
    monkeypatch.setattr(mod, "http_json", lambda path, **k: data)
    code, evidence = run(mod, capsys)
    assert code == 3
    assert evidence["state"] == "local_weights_not_verified"


def test_smoke_uses_exact_local_model_and_checks_loaded_weights(monkeypatch, capsys):
    mod = module()
    calls = []

    def fake_http(path, *, payload=None, timeout=10):
        calls.append(path)
        if path == "/api/tags":
            return weights()
        if path == "/api/generate":
            assert timeout == 120
            assert payload["model"] == "qwen2.5-coder:7b"
            assert payload["options"]["num_ctx"] == 2048
            assert payload["options"]["num_predict"] == 32
            assert payload["format"]["properties"]["sentinel"]["enum"] == ["OLLAMA_CPU_PILOT_OK"]
            assert payload["format"]["additionalProperties"] is False
            assert payload["stream"] is False
            return generation()
        if path == "/api/ps":
            return loaded()
        raise AssertionError("unexpected API path")

    monkeypatch.setattr(mod, "http_json", fake_http)
    code, evidence = run(mod, capsys, "smoke")
    assert code == 0
    assert evidence["state"] == "smoke_validated"
    assert evidence["tokens_per_second"] == 4.0
    assert evidence["local_loaded_digest_verified"] is True
    assert evidence["vram_bytes"] == 0
    assert calls == ["/api/tags", "/api/generate", "/api/ps"]


@pytest.mark.parametrize(
    "broken,reason",
    [
        ({"model": "different:7b"}, "model_identity_mismatch"),
        ({"response": "model failed to obey"}, "response_json_invalid"),
        ({"done": False}, "generation_incomplete"),
        ({"response": json.dumps({"sentinel": "WRONG"})}, "response_contract_mismatch"),
        ({"response": json.dumps({"sentinel": "OLLAMA_CPU_PILOT_OK", "extra": True})}, "response_contract_mismatch"),
        ({"response": 5}, "response_schema_invalid"),
        ({"eval_count": 0}, "inference_metrics_missing"),
    ],
)
def test_inference_rejects_false_positives(monkeypatch, capsys, broken, reason):
    mod = module()
    def fake_http(path, **kwargs):
        if path == "/api/tags":
            return weights()
        if path == "/api/generate":
            return {**generation(), **broken}
        return loaded()
    monkeypatch.setattr(mod, "http_json", fake_http)
    code, evidence = run(mod, capsys, "smoke")
    assert code == 3
    assert evidence["state"] == reason


def test_wrong_loaded_digest_is_blocked(monkeypatch, capsys):
    mod = module()
    def fake_http(path, **kwargs):
        if path == "/api/tags":
            return weights()
        if path == "/api/generate":
            return generation()
        return {"models": [{"name": "qwen2.5-coder:7b", "digest": "b" * 64, "context_length": 2048}]}
    monkeypatch.setattr(mod, "http_json", fake_http)
    code, evidence = run(mod, capsys, "smoke")
    assert code == 3
    assert evidence["state"] == "local_loaded_model_not_verified"


def test_unreachable_does_not_leak_provider_error(monkeypatch, capsys):
    mod = module()
    def unavailable(path, **kwargs):
        raise mod.PilotBlocked("ollama_unreachable")
    monkeypatch.setattr(mod, "http_json", unavailable)
    code, evidence = run(mod, capsys)
    assert code == 3
    assert evidence["state"] == "ollama_unreachable"
    assert "traceback" not in json.dumps(evidence).lower()


def test_invalid_inputs_and_endpoint_are_rejected():
    mod = module()
    with pytest.raises(SystemExit, match="invalid_correlation_id"):
        mod.main(["--mode", "inventory", "--correlation-id", "bad;id"])
    with pytest.raises(mod.PilotBlocked, match="endpoint_not_allowed"):
        mod.http_json("/api/pull")


def test_physical_workflow_is_explicitly_gated_governed_and_bounded():
    content = WORKFLOW.read_text(encoding="utf-8")
    trigger = content.split("\npermissions:", 1)[0]
    assert "  workflow_dispatch:" in trigger
    assert "\n  push:" not in trigger
    assert "\n  pull_request:" in trigger
    assert "types: [ready_for_review]" in trigger
    assert "types: [opened" not in trigger
    assert "types: [synchronize" not in trigger
    assert "head.ref == 'feat/ollama-cpu-pilot-dev-20261024'" in content
    assert "head.repo.full_name == github.repository" in content
    assert "'smoke' || inputs.mode" in content
    assert "\n  schedule:" not in trigger
    assert "refs/heads/main" in content
    assert "self-hosted, Windows, X64, pc24x7" in content
    assert "session_launcher.py" in content
    assert "command_gateway.py" in content
    assert "SESSION_LAUNCH_OK" in content
    assert "physical_runner_watchdog:" in content
    assert "cancelWorkflowRun" in content
    assert "STALL_AFTER_SECONDS: \"60\"" in content
    assert "/api/pull" not in content
    assert "docker " not in content.lower()



def test_current_rules_are_pinned_once_for_both_physical_jobs():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    resolver = jobs["resolve_rules"]
    assert resolver["runs-on"] == "ubuntu-latest"
    assert resolver["outputs"]["sha"] == "${{ steps.resolve.outputs.sha }}"
    assert "github.actor == 'ericson-j-santos'" in resolver["if"]
    assert "github.rest.repos.getBranch" in resolver["steps"][0]["with"]["script"]
    assert "OLLAMA_RULES_SHA_UNVERIFIED" in resolver["steps"][0]["with"]["script"]
    for name in ("pilot", "physical_runner_watchdog"):
        job = jobs[name]
        assert job["needs"] == "resolve_rules"
        assert "needs.resolve_rules.result == 'success'" in job["if"]
        assert "RULES_SHA" not in job.get("env", {})
        assert any(
            step.get("with", {}).get("ref") == "${{ needs.resolve_rules.outputs.sha }}"
            and step.get("with", {}).get("repository") == "ericson-j-santos/chatgpt-operational-rules"
            for step in job["steps"]
        )
    assert "6edb5990c777d487c41fb9ee48ccbf411b11d661" not in WORKFLOW.read_text(encoding="utf-8")
    assert all(step.get("uses") != "actions/upload-artifact@v4" for step in resolver["steps"])


def _exercise_github_script(script: str, observed: str, expected: str = "") -> dict:
    """Run the actual Actions JS admission logic with deterministic fake GitHub API."""
    import subprocess

    harness = """
const Script = Object.getPrototypeOf(async function(){}).constructor;
const source = process.argv[1], observed = process.argv[2], expected = process.argv[3];
process.env.EXPECTED_RULES_SHA = expected;
const outputs = {}, errors = [];
const github = {rest:{repos:{getBranch: async ({owner, repo, branch}) => {
  if (owner !== 'ericson-j-santos' || repo !== 'chatgpt-operational-rules' || branch !== 'main')
    throw new Error('unexpected_source');
  return {data:{commit:{sha:observed}}};
}}}};
const core = {
  setFailed: reason => errors.push(reason),
  setOutput: (key, value) => { outputs[key] = value; },
  info: () => {},
};
(async () => {
  await new Script('github', 'core', source)(github, core);
  process.stdout.write(JSON.stringify({outputs, errors}));
})().catch(err => { console.error(err.message); process.exitCode = 9; });
"""
    done = subprocess.run(
        ["node", "-e", harness, script, observed, expected],
        capture_output=True, text=True, check=False, timeout=20,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_source_gate_rejects_invalid_sha_and_drift_using_real_embedded_js():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    resolver_js = jobs["resolve_rules"]["steps"][0]["with"]["script"]
    recheck = next(
        step for step in jobs["pilot"]["steps"]
        if step.get("name") == "Recheck rules main has not drifted before bootstrap"
    )
    assert recheck["env"]["EXPECTED_RULES_SHA"] == "${{ needs.resolve_rules.outputs.sha }}"
    recheck_js = recheck["with"]["script"]
    sha = "a" * 40
    assert _exercise_github_script(resolver_js, sha) == {
        "outputs": {"sha": sha}, "errors": [],
    }
    assert _exercise_github_script(resolver_js, "short")["errors"] == [
        "OLLAMA_RULES_SHA_UNVERIFIED"
    ]
    assert _exercise_github_script(recheck_js, sha, sha)["errors"] == []
    assert _exercise_github_script(recheck_js, "b" * 40, sha)["errors"] == [
        "OLLAMA_RULES_SHA_DRIFT"
    ]
    assert _exercise_github_script(recheck_js, sha, "")["errors"] == [
        "OLLAMA_RULES_SHA_DRIFT"
    ]
