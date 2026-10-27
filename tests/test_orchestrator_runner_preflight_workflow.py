from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/dedicated-runtime-runner-e2e.yml"
SCRIPT = ROOT / "scripts/orchestrator_runner_preflight_workflow.py"
SPEC = importlib.util.spec_from_file_location("orchestrator_runner_preflight_workflow", SCRIPT)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
HEAD, MAIN, RULES = "a" * 40, "b" * 40, "c" * 40
REPO = "ericson-j-santos/desktop-pc24x7-runtime"
PHYSICAL = "Pickup on dedicated Desktop runtime runner"
CONTRACT = "Orchestrator preflight contract on exact SHA"
ADMIT = "Admit orchestrator preflight at current source and successful native CI"
GUARD = "Reject stale orchestrator pickup before checkout or bootstrap"
PROOF = "Prove orchestrator readonly preflight, negative SHA and replay through Command Gateway"
READBACK = "Read actual jobs and require exact terminal preflight evidence"
START_MS = 1800000000000


def workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def step(name):
    matches = [
        step for job in workflow()["jobs"].values()
        for step in job.get("steps", []) if step.get("name") == name
    ]
    assert len(matches) == 1
    return matches[0]


def good_step(name):
    return {"name": name, "status": "completed", "conclusion": "success"}


def good_job(name, run_id, labels, names, **extra):
    return {
        "name": name, "run_id": run_id, "status": "completed", "conclusion": "success",
        "started_at": "2027-01-15T08:00:00Z", "completed_at": "2027-01-15T08:01:00Z",
        "labels": labels, "steps": [good_step(name) for name in names], **extra,
    }


def receipt():
    return {
        "schema_version": 1, "kind": "orchestrator-runner-readonly-preflight",
        "source_sha": HEAD, "rules_sha": RULES, "main_sha": MAIN,
        "source_pr": 113, "ci_run_id": 90, "ci_attempt": 1,
        "run_id": 77, "run_attempt": 1, "correlation_id": "dedicated-runner-77-1",
        "host": m.HOST, "runner_name": m.RUNNER, "runner_id": 2,
        "target_repository": m.TARGET, "target_environment": "dev",
        "negative_state": "source_sha_mismatch", "negative_exit_code": 2,
        "replay_identical": True, "gateway_state_unchanged": True, "read_only": True,
        "registration_required": True, "observed_target_runner_id": None,
        **{key: False for key in m.FALSE_FIELDS},
    }


def js_input():
    branch = "feat/orchestrator-preflight"
    ci = {
        "id": 90, "head_sha": HEAD, "head_branch": branch, "event": "push",
        "status": "completed", "conclusion": "success", "run_attempt": 1,
        "created_at": "2027-01-15T08:00:00Z",
        "repository": {"full_name": REPO},
    }
    ci_jobs = [
        good_job(name, 90, [label], ["Compile", "Unit and negative-control tests"])
        for name, label in [
            ("Python compile and tests", "windows-latest"),
            ("Portable Linux compile and tests", "ubuntu-latest"),
        ]
    ]
    return {
        "now": START_MS, "host": m.HOST, "current": HEAD, "main": MAIN, "rules": RULES,
        "context": {
            "eventName": "workflow_dispatch", "actor": "ericson-j-santos",
            "repo": {"owner": "ericson-j-santos", "repo": "desktop-pc24x7-runtime"},
            "ref": "refs/heads/" + branch, "sha": HEAD, "runId": 77,
            "payload": {"inputs": {"lenovo_control_plane_pickup": "false"}},
        },
        "env": {
            "ORCHESTRATOR_SOURCE_SHA": HEAD, "GITHUB_RUN_ATTEMPT": "1",
            "ORCHESTRATOR_ADMITTED_AT": datetime.fromtimestamp(START_MS / 1000, timezone.utc).isoformat(),
            "RUNNER_NAME": m.RUNNER, "ORCHESTRATOR_MAIN_SHA": MAIN, "RULES_SHA": RULES,
            "PHYSICAL_RESULT": "success", "CONTRACT_RESULT": "success",
            "ORCHESTRATOR_SOURCE_PR": "113", "ORCHESTRATOR_CI_RUN_ID": "90",
            "ORCHESTRATOR_CI_ATTEMPT": "1", "RECEIPT": json.dumps(receipt()),
        },
        "pulls": [{
            "number": 113, "state": "open",
            "head": {"sha": HEAD, "ref": branch, "repo": {"full_name": REPO}},
            "base": {"sha": MAIN, "ref": "main", "repo": {"full_name": REPO}},
        }],
        "comparison": {"status": "ahead", "merge_base_commit": {"sha": MAIN}},
        "ci": ci, "ci_runs": [ci], "ci_jobs": {"total_count": 2, "jobs": ci_jobs},
        "workflow_jobs": {"total_count": 2, "jobs": [
            good_job(PHYSICAL, 77, ["self-hosted", "Windows", "X64"], [
                GUARD, "Bootstrap governed session and runner version preflight", PROOF,
            ], runner_id=2, runner_name=m.RUNNER),
            good_job(CONTRACT, 77, ["windows-latest"], ["Focused preflight and workflow contract"]),
        ]},
    }


NODE_HARNESS = r"""
'use strict';
const fs = require('node:fs'), vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8')), data = input.data;
const outputs = {}, calls = [];
class TestDate extends Date {
  constructor(...args) { super(...(args.length ? args : [data.now])); }
  static now() { return data.now; }
}
const record = (name, value) => { calls.push(name); return {data: value}; };
const github = {rest: {
  repos: {
    getBranch: async args => record('branch', {commit: {sha:
      args.repo === 'chatgpt-operational-rules' ? data.rules :
      args.branch === 'main' ? data.main : data.current}}),
    compareCommits: async () => record('compare', data.comparison),
  },
  pulls: {
    list: async () => record('pulls', data.pulls),
    get: async () => record('pull', data.pulls[0]),
  },
  actions: {
    listWorkflowRuns: async () => record('ci_runs', {workflow_runs: data.ci_runs}),
    getWorkflowRun: async () => record('ci', data.ci),
    listJobsForWorkflowRun: async args => record('jobs',
      args.run_id === 90 ? data.ci_jobs : data.workflow_jobs),
  },
}};
const summary = {addHeading() { return this; }, addCodeBlock() { return this; }, async write() {}};
const sandbox = {
  github, context: data.context, process: {env: data.env}, Date: TestDate,
  core: {setOutput: (name, value) => { outputs[name] = value; }, info() {}, summary},
  require: name => {
    if (name !== 'os') throw new Error('UNEXPECTED_MODULE');
    return {hostname: () => data.host};
  },
};
(async () => {
  let error = null;
  try {
    await vm.runInNewContext('(async () => {\n' + input.source + '\n})()', sandbox, {timeout: 1000});
  } catch (failure) { error = failure.message; }
  process.stdout.write(JSON.stringify({error, outputs, calls}));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
"""


def execute_step(name, data, tmp_path):
    node = shutil.which("node")
    assert node, "Node is required to execute the real workflow gates; do not skip."
    harness = tmp_path / "orchestrator-workflow-harness.cjs"
    harness.write_text(NODE_HARNESS, encoding="utf-8")
    completed = subprocess.run(
        [node, str(harness)],
        input=json.dumps({"source": step(name)["with"]["script"], "data": data}),
        text=True, capture_output=True, timeout=10, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_real_admission_accepts_exact_current_pr_and_two_native_ci_jobs(tmp_path):
    observed = execute_step(ADMIT, js_input(), tmp_path)
    assert observed["error"] is None
    assert observed["outputs"] == {
        "main_sha": MAIN, "source_pr": "113", "ci_run_id": "90", "ci_attempt": "1",
    }


@pytest.mark.parametrize("case", [
    "old_input", "moved_head", "stale_main", "foreign_pr", "missing_pr",
    "skipped_ci", "missing_ci_step", "wrong_ci_label", "incomplete_ci", "rerun",
    "newer_pending_ci", "newer_failed_ci",
])
def test_real_admission_rejects_unproved_state(case, tmp_path):
    data = js_input()
    if case == "old_input":
        data["env"]["ORCHESTRATOR_SOURCE_SHA"] = "d" * 40
    elif case == "moved_head":
        data["current"] = "d" * 40
    elif case == "stale_main":
        data["comparison"]["merge_base_commit"]["sha"] = "d" * 40
    elif case == "foreign_pr":
        data["pulls"][0]["head"]["repo"]["full_name"] = "other/repository"
    elif case == "missing_pr":
        data["pulls"] = []
    elif case == "skipped_ci":
        data["ci_jobs"]["jobs"][0]["conclusion"] = "skipped"
    elif case == "missing_ci_step":
        data["ci_jobs"]["jobs"][1]["steps"] = [good_step("Compile")]
    elif case == "wrong_ci_label":
        data["ci_jobs"]["jobs"][1]["labels"] = ["self-hosted"]
    elif case == "incomplete_ci":
        data["ci_jobs"]["total_count"] = 3
    elif case == "rerun":
        data["env"]["GITHUB_RUN_ATTEMPT"] = "2"
    elif case in {"newer_pending_ci", "newer_failed_ci"}:
        newer = dict(data["ci"], id=91, created_at="2027-01-15T08:02:00Z")
        if case == "newer_pending_ci":
            newer.update(status="queued", conclusion=None)
        else:
            newer.update(conclusion="failure")
        data["ci_runs"] = [data["ci"], newer]
    observed = execute_step(ADMIT, data, tmp_path)
    assert observed["error"].startswith("ORCHESTRATOR_PREFLIGHT_")
    assert observed["outputs"] == {}


@pytest.mark.parametrize("case", ["valid", "expired", "wrong_runner_id", "wrong_host", "moved_rules", "moved_main"])
def test_real_pickup_guard_enforces_identity_freshness_and_rules(case, tmp_path):
    data = js_input()
    data["workflow_jobs"]["jobs"][0]["status"] = "in_progress"
    if case == "expired":
        data["now"] += 300001
    elif case == "wrong_runner_id":
        data["workflow_jobs"]["jobs"][0]["runner_id"] = 24
    elif case == "wrong_host":
        data["host"] = "DESKTOP-RP23OGS"
    elif case == "moved_rules":
        data["rules"] = "d" * 40
    elif case == "moved_main":
        data["main"] = "d" * 40
    observed = execute_step(GUARD, data, tmp_path)
    assert (observed["error"] is None) == (case == "valid")


@pytest.mark.parametrize("case", [
    "valid", "skipped_job", "missing_physical_step", "wrong_runner_id", "missing_contract_step",
    "old_receipt_sha", "negative_not_proven", "replay_not_proven", "mutating_receipt",
    "ci_rerun", "head_moved", "pr_closed", "physical_failure",
    "readback_rerun", "newer_ci_started", "newer_ci_failed",
])
def test_independent_readback_uses_actual_jobs_and_semantic_receipt(case, tmp_path):
    data = js_input()
    record = receipt()
    if case == "skipped_job":
        data["workflow_jobs"]["jobs"][0]["conclusion"] = "skipped"
    elif case == "missing_physical_step":
        data["workflow_jobs"]["jobs"][0]["steps"].pop()
    elif case == "wrong_runner_id":
        data["workflow_jobs"]["jobs"][0]["runner_id"] = 24
    elif case == "missing_contract_step":
        data["workflow_jobs"]["jobs"][1]["steps"] = []
    elif case == "old_receipt_sha":
        record["source_sha"] = "d" * 40
    elif case == "negative_not_proven":
        record["negative_state"] = "source_readback_unavailable"
    elif case == "replay_not_proven":
        record["replay_identical"] = False
    elif case == "mutating_receipt":
        record["registration_performed"] = True
    elif case == "ci_rerun":
        data["ci"]["run_attempt"] = 2
    elif case == "head_moved":
        data["current"] = "d" * 40
    elif case == "pr_closed":
        data["pulls"][0]["state"] = "closed"
    elif case == "physical_failure":
        data["env"]["PHYSICAL_RESULT"] = "failure"
    elif case == "readback_rerun":
        data["env"]["GITHUB_RUN_ATTEMPT"] = "2"
    elif case in {"newer_ci_started", "newer_ci_failed"}:
        newer = dict(data["ci"], id=91, created_at="2027-01-15T08:02:00Z")
        if case == "newer_ci_started":
            newer.update(status="in_progress", conclusion=None)
        else:
            newer.update(conclusion="failure")
        data["ci_runs"] = [data["ci"], newer]
    data["env"]["RECEIPT"] = json.dumps(record)
    observed = execute_step(READBACK, data, tmp_path)
    assert (observed["error"] is None) == (case == "valid")


@pytest.fixture
def physical(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    target = tmp_path / "target"
    for path in (
        workspace / "_rules/scripts/command_gateway.py",
        workspace / "_rules/config/command-gateway.policy.json",
        target / "scripts/orchestrator_dev_runner_preflight.py",
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n", encoding="utf-8")
    values = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": REPO, "GITHUB_SHA": HEAD, "ANCHOR_SHA": HEAD,
        "GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "1",
        "RULES_SHA": RULES, "ORCHESTRATOR_MAIN_SHA": MAIN,
        "ORCHESTRATOR_CI_RUN_ID": "90", "ORCHESTRATOR_CI_ATTEMPT": "1",
        "ORCHESTRATOR_SOURCE_PR": "113", "RUNNER_NAME": m.RUNNER,
        "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
        "CORRELATION_ID": "dedicated-runner-77-1", "SESSION_ID": "session-77",
        "GITHUB_WORKSPACE": str(workspace), "TARGET_PATH": str(target),
        "GITHUB_OUTPUT": str(tmp_path / "output.txt"),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.HOST)
    return tmp_path


def positive_payload():
    return {
        "ok": True, "state": "READ_ONLY_PLAN_RECORDED_EXECUTION_PENDING",
        "mode": "preflight_only", "source_sha": HEAD,
        "correlation_id": "dedicated-runner-77-1", "read_only": True,
        "profile": {
            "target": "orchestrator-dev", "environment": "dev",
            "repository": m.TARGET, "host": m.HOST, "runner_name": m.HOST + "-orchestrator-dev",
        },
        "registration_required": True, "observed_runner_id": None,
        "runner_home": "private-local-path-must-not-be-reported",
        **{key: False for key in m.FALSE_FIELDS},
    }


def gateway_completion(payload, negative=False, changed=False):
    code = 2 if negative else 0
    event = {
        "action": "run", "risk": 1, "session_id": "session-77",
        "correlation_id": "dedicated-runner-77-1", "gateway_exit_code": code,
        "command_exit_code": code, "state_changed": changed,
        "result": "command_failed" if negative else "ok",
        "before": {"head": HEAD}, "after": {"head": HEAD}, "stdout": json.dumps(payload),
    }
    return SimpleNamespace(returncode=code, stdout=json.dumps(event), stderr="")


def negative_payload():
    return {
        "ok": False, "state": "source_sha_mismatch", "read_only": True,
        "execution_authorized": False, "registration_performed": False,
        "registration_token_requested": False,
    }


def test_fixed_helper_runs_negative_and_replay_via_gateway_and_sanitizes_receipt(physical, monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["shell"] is False
        assert command[command.index("--expected-head") + 1] == HEAD
        assert command[command.index("--risk") + 1] == "1"
        negative = command[command.index("--expected-sha") + 1] != HEAD
        return gateway_completion(negative_payload() if negative else positive_payload(), negative)

    monkeypatch.setattr(m.subprocess, "run", run)
    m.prove()
    assert len(commands) == 3
    assert [command[command.index("--expected-sha") + 1] for command in commands] == ["0" * 40, HEAD, HEAD]
    raw = (physical / "output.txt").read_text(encoding="utf-8").removeprefix("receipt=").strip()
    assert json.loads(raw) == receipt()
    assert "private-local-path" not in raw


@pytest.mark.parametrize("case", ["wrong_host", "bad_negative", "replay_changed", "gateway_changed", "wrong_source"])
def test_fixed_helper_blocks_without_publishing_false_receipt(physical, monkeypatch, case):
    calls = 0

    def run(command, **kwargs):
        nonlocal calls
        calls += 1
        negative = calls == 1
        payload = negative_payload() if negative else positive_payload()
        if case == "bad_negative" and negative:
            payload["state"] = "github_api_failed"
        if case == "replay_changed" and calls == 3:
            payload["runner_home"] = "changed"
        if case == "wrong_source" and not negative:
            payload["source_sha"] = "d" * 40
        return gateway_completion(payload, negative, changed=case == "gateway_changed")

    monkeypatch.setattr(m.subprocess, "run", run)
    if case == "wrong_host":
        monkeypatch.setattr(m.socket, "gethostname", lambda: "DESKTOP-RP23OGS")
    with pytest.raises(m.WorkflowBlocked):
        m.prove()
    assert not (physical / "output.txt").exists()
    if case == "wrong_host":
        assert calls == 0


def test_new_route_preserves_existing_modes_upload_and_uses_governed_session():
    jobs = workflow()["jobs"]
    e2e = jobs["e2e"]
    names = [item["name"] for item in e2e["steps"]]
    assert names.index(GUARD) < names.index("Checkout exact runtime SHA")
    assert names.index("Bootstrap governed session and runner version preflight") < names.index(PROOF)
    assert "orchestrator_contract" in e2e["needs"]
    assert "needs.orchestrator_contract.result == 'success'" in e2e["if"]
    assert "orchestrator-runner-preflight" in step("Upload sanitized evidence")["if"]
    assert step("Upload sanitized evidence")["with"]["if-no-files-found"] == "error"
    assert "lenovo_control_plane_pickup" in jobs["lenovo_pickup"]["if"]
    assert step(PROOF)["shell"] == "python"
    assert step(PROOF)["env"]["GH_TOKEN"] == ""
    assert step(PROOF)["env"]["GITHUB_TOKEN"] == ""
    assert "--require-runner-version-preflight" in step("Bootstrap governed session and runner version preflight")["run"]
    assert "orchestrator_contract" in jobs["queue_watchdog"]["needs"]
    for job_name in ("e2e", "queue_watchdog"):
        assert jobs[job_name]["if"].startswith("$" + "{{ !cancelled() && ")
        assert "always()" not in jobs[job_name]["if"]
    assert jobs["orchestrator_preflight_readback"]["permissions"] == {
        "contents": "read", "actions": "read", "pull-requests": "read",
    }


@pytest.mark.skipif(os.name != "nt", reason="PowerShell 5.1 parser is a Windows-only CI gate")
def test_preserved_desktop_bootstrap_parses_in_native_powershell_51():
    executable = shutil.which("powershell")
    assert executable, "Native PowerShell 5.1 must exist in the Windows CI job."
    parser = (
        "$ErrorActionPreference='Stop';"
        "if ($PSVersionTable.PSVersion.Major -ne 5) { exit 2 };"
        "$tokens=$null;$errors=$null;"
        "[System.Management.Automation.Language.Parser]::ParseInput("
        "[Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors) | Out-Null;"
        "if ($errors.Count -gt 0) { exit 3 }"
    )
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", parser],
        input=step("Bootstrap governed session and runner version preflight")["run"],
        text=True, capture_output=True, timeout=20, check=False,
    )
    assert result.returncode == 0, "Existing governed PowerShell bootstrap failed native parsing."
