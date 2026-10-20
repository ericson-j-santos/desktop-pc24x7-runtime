"""Exercise both real portfolio observers with simulated GitHub, clock and filesystem.

No Desktop connection, runner registration, label repair or workflow dispatch.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/portfolio-bridge-preflight-dev.yml"
WATCHDOGS = {
    "prepare_runner_watchdog": "Ensure dedicated Desktop runner labels",
    "preflight_runner_watchdog": "Governed PC24x7 portfolio bridge dry-run",
}
START_MS = 1792072800000
RUNNER = "DESKTOP-PDQK954-runtime"
HARNESS = r"""
'use strict';
const fs = require('node:fs'), vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let clock = input.start_ms, reads = 0;
const writes = [], failures = [], cancellations = [];
class TestDate extends Date {
  constructor(...args) { super(...(args.length ? args : [clock])); }
  static now() { return clock; }
}
const sandbox = {
  github: {rest: {actions: {
    getWorkflowRun: async () => ({data: {
      created_at: new Date(input.start_ms - input.workflow_age_ms).toISOString(),
    }}),
    listJobsForWorkflowRun: async () => {
      if (++reads > 50) throw new Error('OBSERVER_DID_NOT_STOP');
      const job = clock - input.start_ms >= input.pickup_after_ms
        ? input.final_job : input.queued_job;
      return {data: {jobs: [job], total_count: 1}};
    },
    cancelWorkflowRun: async args => { cancellations.push(args.run_id); },
  }}},
  context: {repo: {owner: 'ericson-j-santos', repo: 'desktop-pc24x7-runtime'}},
  core: {setFailed: reason => failures.push(reason)},
  process: {env: {
    TARGET_RUN_ID: '77', TARGET_JOB_NAME: input.job_name,
    STALL_AFTER_SECONDS: input.stall_seconds, CORRELATION_ID: 'portfolio-regression',
  }},
  Date: TestDate,
  setTimeout: (callback, ms) => {
    if (!Number.isFinite(ms) || ms <= 0 || ms > 15000) throw new Error('INVALID_SLEEP');
    clock += ms; callback();
  },
  require: name => {
    if (name !== 'fs') throw new Error('MODULE_NOT_ALLOWED_IN_TEST');
    return {writeFileSync: (name, data) => writes.push({name, data: JSON.parse(data)})};
  },
};
(async () => {
  await vm.runInNewContext('(async () => {\n' + input.source + '\n})()', sandbox, {timeout: 1000});
  process.stdout.write(JSON.stringify({
    writes, failures, cancellations, reads, elapsed_ms: clock - input.start_ms,
  }));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
"""


def job_block(key: str) -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    marker = f"\n  {key}:\n"
    assert text.count(marker) == 1
    return re.split(r"\n  [A-Za-z_]+:\n", text.split(marker, 1)[1], maxsplit=1)[0]


def observer_source(key: str) -> str:
    block = job_block(key)
    marker = "      - name: Observe physical runner pickup\n"
    assert block.count(marker) == 1
    step = block.split(marker, 1)[1].split("\n      - name:", 1)[0]
    lines = step.split("          script: |\n", 1)[1].rstrip().splitlines()
    assert all(line.startswith("            ") or not line.strip() for line in lines)
    return "\n".join(line[12:] for line in lines) + "\n"


def job(key: str, **changes: object) -> dict:
    value = {
        "id": 88, "run_id": 77, "name": WATCHDOGS[key],
        "status": "queued", "conclusion": None, "runner_id": 0, "runner_name": "",
    }
    value.update(changes)
    return value


def observe(key: str, final_job: dict, *, pickup_after_ms: int = 0,
            workflow_age_ms: int = 600_000) -> dict:
    budget = re.search(r'STALL_AFTER_SECONDS: "(\d+)"', job_block(key))
    assert budget is not None
    node = shutil.which("node")
    assert node, "Node.js is required to test workflow JavaScript; do not skip."
    payload = {
        "source": observer_source(key), "start_ms": START_MS,
        "workflow_age_ms": workflow_age_ms, "pickup_after_ms": pickup_after_ms,
        "stall_seconds": budget.group(1), "job_name": WATCHDOGS[key],
        "queued_job": job(key), "final_job": final_job,
    }
    with tempfile.TemporaryDirectory(prefix="portfolio-pickup-test-") as directory:
        harness = Path(directory) / "observer.cjs"
        harness.write_text(HARNESS, encoding="utf-8")
        result = subprocess.run(
            [node, str(harness)], input=json.dumps(payload), text=True,
            capture_output=True, timeout=10, check=False,
        )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("key", WATCHDOGS)
def test_setup_does_not_consume_the_downstream_pickup_window(key: str) -> None:
    result = observe(key, job(key, status="in_progress", runner_id=9, runner_name=RUNNER),
                     pickup_after_ms=150_000)
    assert result["elapsed_ms"] == 150_000
    assert len(result["writes"]) == 1
    assert result["writes"][0]["data"]["state"] == "running"
    assert result["failures"] == result["cancellations"] == []


@pytest.mark.parametrize("key", WATCHDOGS)
def test_stall_is_bounded_without_polling_renewing_progress(key: str) -> None:
    result = observe(key, job(key))
    assert result["elapsed_ms"] == 300_000
    assert result["reads"] == 21
    assert len(result["writes"]) == 1
    record = result["writes"][0]["data"]
    assert record["state"] == "queued"
    assert record["last_material_progress_at"] == "2026-10-15T14:00:00.000Z"
    assert record["last_observation_at"] == "2026-10-15T14:05:00.000Z"


@pytest.mark.parametrize("key", WATCHDOGS)
@pytest.mark.parametrize("state,conclusion", [("in_progress", None), ("completed", "success")])
def test_exact_runner_and_current_run_are_observed(key: str, state: str, conclusion: str | None) -> None:
    result = observe(key, job(key, status=state, conclusion=conclusion, runner_id=9, runner_name=RUNNER))
    assert result["elapsed_ms"] == 0
    assert len(result["writes"]) == 1
    assert result["writes"][0]["data"]["state"] == ("running" if state == "in_progress" else "completed")


@pytest.mark.parametrize("key", WATCHDOGS)
@pytest.mark.parametrize("changes", [
    {"status": "waiting", "runner_id": 0, "runner_name": ""},
    {"status": "completed", "conclusion": "skipped", "runner_id": 0, "runner_name": ""},
    {"runner_name": "DESKTOP-RP23OGS-runtime"},
    {"run_id": 76},
    {"status": "queued"},
    {"runner_id": True},
    {"runner_id": "9"},
    {"runner_id": 1.5},
    {"id": 0},
    {"status": "completed", "conclusion": "skipped"},
])
def test_unassigned_status_wrong_identity_or_skipped_is_not_pickup(key: str, changes: dict) -> None:
    candidate = job(key, status="in_progress", runner_id=9, runner_name=RUNNER)
    candidate.update(changes)
    result = observe(key, candidate, workflow_age_ms=0)
    assert result["elapsed_ms"] == 300_000
    assert len(result["writes"]) == 1
    assert result["writes"][0]["data"]["state"] == "queued"
    assert result["cancellations"] == []


@pytest.mark.parametrize("key", WATCHDOGS)
def test_replay_is_deterministic_and_does_not_dispatch_or_repair(key: str) -> None:
    first, second = observe(key, job(key)), observe(key, job(key))
    assert first == second
    assert len(first["writes"]) == 1
    assert first["cancellations"] == []
    source = observer_source(key)
    for forbidden in ("createWorkflowDispatch", "updateSelfHostedRunner", "exec(", "spawn("):
        assert forbidden not in source


@pytest.mark.parametrize("key", WATCHDOGS)
def test_existing_admission_and_final_cancellation_controls_remain(key: str) -> None:
    block = job_block(key)
    assert "!github.event.pull_request.draft" in block
    assert "github.event.pull_request.head.repo.full_name == github.repository" in block
    assert 'STALL_AFTER_SECONDS: "300"' in block
    assert "timeout-minutes: 7" in block
    assert "progress_watchdog.py" in block
    assert "if: steps.watchdog.outcome == 'failure'" in block
    assert "decision.decision !== 'block'" in block
    assert "cancelWorkflowRun" in block
