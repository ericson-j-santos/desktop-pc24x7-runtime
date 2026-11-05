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
    assert "  issue_comment:" in trigger
    assert "types: [created]" in trigger
    assert "\n  push:" not in trigger
    assert "\n  pull_request:" in trigger
    assert "types: [ready_for_review, edited]" in trigger
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
    assert "inputs.mode == 'inventory'" in resolver["if"]
    assert "inputs.candidate_sha == github.sha" in resolver["if"]
    assert "github.ref != 'refs/heads/main'" in resolver["if"]
    assert "OLLAMA_DRAFT_PR_OR_BASE_DRIFT" in resolver["steps"][0]["with"]["script"]
    assert "github.event.pull_request.number == 138" in resolver["if"]
    assert "github.event.action == 'edited'" in resolver["if"]
    assert "github.actor == 'ericson-j-santos'" in resolver["if"]
    assert resolver["permissions"]["checks"] == "read"
    assert resolver["permissions"]["issues"] == "read"
    assert resolver["permissions"]["actions"] == "read"
    assert "github.rest.checks.listForRef" in resolver["steps"][0]["with"]["script"]
    assert "TODO39_HOSTED_PREFLIGHT_ONLY" in resolver["steps"][0]["with"]["script"]
    assert "NO_PHYSICAL_DISPATCH:NO_MODEL_INFERENCE" in resolver["steps"][0]["with"]["script"]
    assert resolver["permissions"]["pull-requests"] == "read"
    assert "github.rest.repos.getBranch" in resolver["steps"][0]["with"]["script"]
    assert "OLLAMA_RULES_SHA_UNVERIFIED" in resolver["steps"][0]["with"]["script"]
    for name in ("pilot", "physical_runner_watchdog"):
        job = jobs[name]
        assert job["needs"] == "resolve_rules"
        assert "github.event.action != 'edited'" in job["if"]
        assert "needs.resolve_rules.result == 'success'" in job["if"]
        assert "RULES_SHA" not in job.get("env", {})
        assert any(
            step.get("with", {}).get("ref") == "${{ needs.resolve_rules.outputs.sha }}"
            and step.get("with", {}).get("repository") == "ericson-j-santos/chatgpt-operational-rules"
            for step in job["steps"]
        )
    assert "6edb5990c777d487c41fb9ee48ccbf411b11d661" not in WORKFLOW.read_text(encoding="utf-8")
    assert all(step.get("uses") != "actions/upload-artifact@v4" for step in resolver["steps"])


def _exercise_github_script(script: str, observed: str, expected: str = "", route: dict | None = None) -> dict:
    """Run the actual Actions JS admission logic with deterministic fake GitHub API."""
    import subprocess

    harness = """
const Script = Object.getPrototypeOf(async function(){}).constructor;
const source = process.argv[1], observed = process.argv[2], expected = process.argv[3];
process.env.EXPECTED_RULES_SHA = expected;
process.env.GITHUB_RUN_ATTEMPT = '1';
const outputs = {}, errors = [];
const route = JSON.parse(process.argv[4] || '{}');
globalThis.context = {
  eventName: route.eventName || 'workflow_dispatch',
  ref: route.ref || 'refs/heads/main',
  actor: route.actor || 'ericson-j-santos',
  sha: route.sha || 'a'.repeat(40),
  repo: {owner:'ericson-j-santos', repo:'desktop-pc24x7-runtime'},
  payload: {
    action: route.action || '',
    inputs: {candidate_sha: route.candidate_sha || ''},
    pull_request: route.pull_request || {},
    comment: route.comment || {},
    issue: route.issue || {},
    changes: {body: {from: route.oldBody ?? ''}},
  },
};
const github = {rest:{
  repos:{getBranch: async ({owner, repo, branch}) => {
    if (owner !== 'ericson-j-santos') throw new Error('unexpected_owner');
    if (repo === 'chatgpt-operational-rules' && branch === 'main')
      return {data:{commit:{sha:observed}}};
    if (repo === 'desktop-pc24x7-runtime' && branch === 'main')
      return {data:{commit:{sha:route.base_sha || 'c'.repeat(40)}}};
    if (repo === 'desktop-pc24x7-runtime' &&
        (branch === (route.expected_branch || '') || branch === (route.ref || '').slice(11)))
      return {data:{commit:{sha:route.branch_sha || route.sha}}};
    throw new Error('unexpected_source');
  }},
  pulls:{
    list: async () => ({data: route.prs || []}),
    get: async () => ({data: route.pull_request || {}}),
  },
  checks:{listForRef: async () => ({data:{check_runs: route.check_runs || []}})},
  issues:{
    listComments: async () => ({data: route.issue_comments || []}),
    getComment: async () => ({data: route.current_comment || route.comment || {}}),
  },
  actions:{
    getWorkflowRun: async () => ({data: {...(route.canary || {}),
      updated_at: route.canaryUpdatedAt || new Date().toISOString()}}),
    listWorkflowRuns: async () => ({data: {workflow_runs: route.ci_runs || []}}),
    listJobsForWorkflowRun: async () => ({data:{jobs: route.canary_jobs || []}}),
  },
}};
github.paginate = async (fn, args) => (await fn(args)).data;
github.rest.repos.get = async () => ({data:{private: route.repo_private ?? false}});
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
        ["node", "-e", harness, script, observed, expected, json.dumps(route or {})],
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



def test_draft_pr_inventory_requires_single_current_sha_and_proper_authorization():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    script = jobs["resolve_rules"]["steps"][0]["with"]["script"]
    sha = "a" * 40
    base = "c" * 40
    branch = "fix/ollama-current-rules-admission-todo39-20261105"
    pr = {
        "state": "open", "draft": True,
        "head": {"ref": branch, "sha": sha, "repo": {
            "full_name": "ericson-j-santos/desktop-pc24x7-runtime",
        }},
        "base": {"ref": "main", "sha": base},
    }
    route = {
        "eventName": "workflow_dispatch",
        "ref": "refs/heads/" + branch,
        "sha": sha,
        "candidate_sha": sha,
        "branch_sha": sha,
        "base_sha": base,
        "prs": [pr],
    }
    assert _exercise_github_script(script, "b" * 40, route=route)["errors"] == []
    assert _exercise_github_script(script, "b" * 40, route={
        **route, "candidate_sha": "d" * 40,
    })["errors"] == ["OLLAMA_CANDIDATE_SHA_UNVERIFIED"]
    assert _exercise_github_script(script, "b" * 40, route={
        **route, "branch_sha": "d" * 40,
    })["errors"] == ["OLLAMA_DRAFT_PR_OR_BASE_DRIFT"]
    assert _exercise_github_script(script, "b" * 40, route={
        **route, "prs": [{**pr, "draft": False}],
    })["errors"] == ["OLLAMA_DRAFT_PR_OR_BASE_DRIFT"]
    assert _exercise_github_script(script, "b" * 40, route={
        **route, "prs": [pr, pr],
    })["errors"] == ["OLLAMA_DRAFT_PR_OR_BASE_DRIFT"]
    assert _exercise_github_script(script, "b" * 40, route={
        **route, "base_sha": "d" * 40,
    })["errors"] == ["OLLAMA_DRAFT_PR_OR_BASE_DRIFT"]


def test_draft_pr_is_rechecked_on_physical_runner_before_bootstrap():
    """A delayed pickup cannot reuse an expired hosted admission."""
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    steps = jobs["pilot"]["steps"]
    gate = next(step for step in steps if step.get("name") ==
                "Recheck draft candidate PR before bootstrap")
    assert gate["if"] == (
        "github.event_name == 'workflow_dispatch' && github.ref != 'refs/heads/main'"
    )
    assert steps.index(gate) < next(
        i for i, step in enumerate(steps)
        if step.get("name") == "Bootstrap governed session"
    )
    script = gate["with"]["script"]
    sha = "a" * 40
    base = "c" * 40
    branch = "fix/ollama-current-rules-admission-todo39-20261105"
    pr = {
        "state": "open", "draft": True,
        "head": {"ref": branch, "sha": sha, "repo": {
            "full_name": "ericson-j-santos/desktop-pc24x7-runtime",
        }},
        "base": {"ref": "main", "sha": base},
    }
    route = {
        "eventName": "workflow_dispatch",
        "ref": "refs/heads/" + branch,
        "sha": sha, "candidate_sha": sha, "branch_sha": sha,
        "base_sha": base, "prs": [pr],
    }
    assert _exercise_github_script(script, "b" * 40, route=route) == {
        "outputs": {}, "errors": [],
    }
    for changed, reason in (
        ({"candidate_sha": "d" * 40}, "OLLAMA_CANDIDATE_SHA_DRIFT_AT_BOOTSTRAP"),
        ({"branch_sha": "d" * 40}, "OLLAMA_DRAFT_PR_DRIFT_AT_BOOTSTRAP"),
        ({"base_sha": "d" * 40}, "OLLAMA_DRAFT_PR_DRIFT_AT_BOOTSTRAP"),
        ({"prs": [{**pr, "draft": False}]}, "OLLAMA_DRAFT_PR_DRIFT_AT_BOOTSTRAP"),
        ({"prs": [pr, pr]}, "OLLAMA_DRAFT_PR_DRIFT_AT_BOOTSTRAP"),
    ):
        assert _exercise_github_script(
            script, "b" * 40, route={**route, **changed}
        )["errors"] == [reason]



def test_pr_edit_auto_preflight_is_hosted_only_and_one_shot():
    import yaml

    conf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert "edited" in conf.get("on", conf.get(True))["pull_request"]["types"]
    jobs = conf["jobs"]
    resolver = jobs["resolve_rules"]
    assert resolver["runs-on"] == "ubuntu-latest"
    for jobname in ("pilot", "physical_runner_watchdog"):
        assert "github.event.action != 'edited'" in jobs[jobname]["if"]
    body_sha = "a" * 40
    base_sha = "c" * 40
    branch = "fix/ollama-current-rules-admission-todo39-20261105"
    marker = "TODO39_AUTOPREFLIGHT_ONCE_" + body_sha
    data = {
        "number": 138, "state": "open", "draft": True,
        "user": {"login": "ericson-j-santos"},
        "head": {"sha": body_sha, "ref": branch, "repo": {
            "full_name": "ericson-j-santos/desktop-pc24x7-runtime",
        }},
        "base": {"ref": "main", "sha": base_sha},
        "body": "Auto-preflight: " + marker,
    }
    checks = [
        {"name": n, "head_sha": body_sha, "status": "completed",
         "conclusion": "success", "started_at": "2026-11-05T01:00:00Z",
         "completed_at": "2026-11-05T01:01:00Z"}
        for n in ("Python compile and tests", "Portable Linux compile and tests")
    ]
    route = {
        "eventName": "pull_request", "action": "edited",
        "ref": "refs/pull/138/merge", "sha": "b" * 40,
        "pull_request": data, "oldBody": "No marker",
        "branch_sha": body_sha, "base_sha": base_sha,
        "expected_branch": branch, "check_runs": checks,
    }
    source = resolver["steps"][0]["with"]["script"]
    assert _exercise_github_script(source, "d" * 40, route=route)["errors"] == []
    rejects = [
        ({**route, "oldBody": marker}, "OLLAMA_PREFLIGHT_ONE_SHOT_INVALID"),
        ({**route, "pull_request": {**data, "body": "marker missing"}},
         "OLLAMA_PREFLIGHT_ONE_SHOT_INVALID"),
        ({**route, "branch_sha": "e" * 40},
         "OLLAMA_PREFLIGHT_PR_CI_OR_COST_UNVERIFIED"),
        ({**route, "check_runs": checks[:1]},
         "OLLAMA_PREFLIGHT_PR_CI_OR_COST_UNVERIFIED"),
        ({**route, "repo_private": True},
         "OLLAMA_PREFLIGHT_PR_CI_OR_COST_UNVERIFIED"),
        ({**route, "pull_request": {**data, "draft": False}},
         "OLLAMA_PREFLIGHT_PR_CI_OR_COST_UNVERIFIED"),
        ({**route, "base_sha": "f" * 40},
         "OLLAMA_PREFLIGHT_PR_CI_OR_COST_UNVERIFIED"),
    ]
    for modified, code in rejects:
        assert _exercise_github_script(source, "d" * 40, route=modified)[
            "errors"
        ] == [code]


def test_owner_issue_comment_inventory_admission_and_negative_controls():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    gate = jobs["resolve_rules"]
    assert gate["runs-on"] == "ubuntu-latest"
    assert "github.event_name == 'issue_comment'" in gate["if"]
    assert "github.event.issue.number == 31" in gate["if"]
    assert gate["permissions"]["issues"] == "read"
    assert gate["permissions"]["actions"] == "read"
    assert jobs["pilot"]["permissions"]["issues"] == "read"
    assert "github.event_name == 'issue_comment' && 'inventory'" in (
        next(x for x in jobs["pilot"]["steps"] if
             x.get("name") == "Execute bounded local CPU pilot through Command Gateway")
        ["env"]["PILOT_MODE"]
    )
    pickup = next(x for x in jobs["pilot"]["steps"] if
                  x.get("name") == "Recheck owner issue comment at physical pickup")
    assert pickup["if"] == "github.event_name == 'issue_comment'"
    assert jobs["pilot"]["steps"].index(pickup) < next(
        i for i, step in enumerate(jobs["pilot"]["steps"])
        if step.get("name") == "Bootstrap governed session"
    )
    sha, canary_id, comment_id = "a" * 40, 42055278298, 1234
    body = f"TODO39_INVENTORY_ONCE_{sha}_{canary_id}"
    comment = {"id": comment_id, "body": body,
               "user": {"login": "ericson-j-santos"}}
    checks = [
        {"name": name, "head_sha": sha, "status": "completed",
         "conclusion": "success", "started_at": "2026-11-05T01:00:00Z",
         "completed_at": "2026-11-05T01:01:00Z"}
        for name in ("Python compile and tests", "Portable Linux compile and tests")
    ]
    route = {
        "eventName": "issue_comment", "action": "created",
        "ref": "refs/heads/main", "sha": sha, "base_sha": sha,
        "issue": {"number": 31}, "comment": comment,
        "current_comment": comment, "issue_comments": [comment],
        "check_runs": checks,
        "ci_runs": [{
            "id": 99, "name": "CI", "event": "push", "head_sha": sha,
            "head_branch": "main", "status": "completed",
            "conclusion": "success", "created_at": "2026-11-05T01:00:00Z"
        }],
        "canary": {
            "id": canary_id, "name": "PC24x7 Runtime Canary",
            "event": "schedule", "head_sha": sha,
            "status": "completed", "conclusion": "success",
        },
        "canary_jobs": [{
            "name": "Runner, Docker and workers canary",
            "status": "completed", "conclusion": "success",
            "runner_name": "DESKTOP-PDQK954-runtime", "runner_id": 2,
            "started_at": "2026-11-05T01:00:00Z",
            "completed_at": "2026-11-05T01:01:00Z"
        }],
    }
    script = gate["steps"][0]["with"]["script"]
    assert _exercise_github_script(script, "b" * 40, route=route)["errors"] == []
    bad = [
        ({**route, "actor": "other"}, "TODO39_COMMENT_SCOPE_INVALID"),
        ({**route, "issue": {"number": 13}}, "TODO39_COMMENT_SCOPE_INVALID"),
        ({**route, "comment": {**comment, "body": body + " more"}},
         "TODO39_COMMENT_SCOPE_INVALID"),
        ({**route, "issue_comments": [comment, comment]},
         "TODO39_CI_COST_OR_CANARY_UNVERIFIED"),
        ({**route, "repo_private": True}, "TODO39_CI_COST_OR_CANARY_UNVERIFIED"),
        ({**route, "check_runs": checks[:1]}, "TODO39_CI_COST_OR_CANARY_UNVERIFIED"),
        ({**route, "ci_runs": []}, "TODO39_CI_COST_OR_CANARY_UNVERIFIED"),
        ({**route, "ci_runs": [{**route["ci_runs"][0], "conclusion": "failure"}]},
         "TODO39_CI_COST_OR_CANARY_UNVERIFIED"),
        ({**route, "canaryUpdatedAt": "2020-01-01T00:00:00Z"},
         "TODO39_CI_COST_OR_CANARY_UNVERIFIED"),
        ({**route, "canary": {**route["canary"], "head_sha": "f" * 40}},
         "TODO39_CI_COST_OR_CANARY_UNVERIFIED"),
        ({**route, "canary_jobs": []}, "TODO39_RUNNER_PICKUP_UNVERIFIED"),
    ]
    for data, code in bad:
        assert _exercise_github_script(script, "b" * 40, route=data)["errors"] == [code]


def test_issue_comment_pickup_rechecks_main_and_comment_before_bootstrap():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    step = next(x for x in jobs["pilot"]["steps"] if
                x.get("name") == "Recheck owner issue comment at physical pickup")
    sha = "a" * 40
    comment = {"id": 1234,
               "body": f"TODO39_INVENTORY_ONCE_{sha}_42055278298",
               "user": {"login": "ericson-j-santos"}}
    route = {"eventName": "issue_comment", "sha": sha, "base_sha": sha,
             "comment": comment, "current_comment": comment}
    script = step["with"]["script"]
    assert _exercise_github_script(script, "b" * 40, route=route)["errors"] == []
    assert _exercise_github_script(script, "b" * 40, route={
        **route, "base_sha": "f" * 40,
    })["errors"] == ["TODO39_PICKUP_SHA_OR_COMMENT_DRIFT"]
    assert _exercise_github_script(script, "b" * 40, route={
        **route, "current_comment": {**comment, "body": "edited"},
    })["errors"] == ["TODO39_PICKUP_SHA_OR_COMMENT_DRIFT"]



def test_untrusted_issue_comments_cannot_cancel_active_pilot():
    import yaml

    content = WORKFLOW.read_text(encoding="utf-8")
    assert "on:\\n  issue_comment:" in content
    config = yaml.safe_load(content)
    group = config["concurrency"]["group"]
    cancellation = config["concurrency"]["cancel-in-progress"]
    assert "github.event.comment.id" in group
    assert "github.event_name == 'issue_comment'" in group
    assert cancellation == "${{ github.event_name != 'issue_comment' }}"
    assert "cancel-in-progress: true" not in content.split("\\nconcurrency:", 1)[1].split("\\njobs:", 1)[0]
