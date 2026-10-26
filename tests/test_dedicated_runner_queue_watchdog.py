"""Regression of the real inline pickup observer; GitHub/time/FS are simulated."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/dedicated-runtime-runner-e2e.yml"
START_MS = 1792072800000
JOB_NAME = "Pickup on dedicated Desktop runtime runner"

NODE_HARNESS = r"""
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let clock = input.start_ms, reads = 0;
const writes = [], failures = [], cancellations = [];
class TestDate extends Date {
  constructor(...args) { super(...(args.length ? args : [clock])); }
  static now() { return clock; }
}
const github = {rest: {actions: {
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
}}};
const sandbox = {
  github,
  context: {repo: {owner: 'ericson-j-santos', repo: 'desktop-pc24x7-runtime'}},
  core: {setFailed: reason => failures.push(reason)},
  process: {env: {
    STALL_AFTER_SECONDS: input.stall_seconds,
    TARGET_RUN_ID: '77',
    TARGET_JOB_NAME: input.job_name,
    EXPECTED_RUNNER: input.expected_runner,
    CORRELATION_ID: 'watchdog-regression',
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


def observer_source(text: str) -> str:
    marker = "      - name: Observe dedicated runner pickup\n"
    assert text.count(marker) == 1
    step = text.split(marker, 1)[1].split("\n      - name:", 1)[0]
    source = step.split("          script: |\n", 1)[1]
    lines = source.rstrip().splitlines()
    assert all(line.startswith("            ") or not line.strip() for line in lines)
    return "\n".join(line[12:] for line in lines) + "\n"


def job(**changes: object) -> dict:
    value = {
        "id": 88, "run_id": 77, "name": JOB_NAME, "status": "queued",
        "conclusion": None, "runner_id": 0, "runner_name": "",
    }
    value.update(changes)
    return value


def observe(
    final_job: dict,
    pickup_after_ms: int = 0,
    workflow_age_ms: int = 120_000,
    expected_runner: str = "DESKTOP-PDQK954-runtime",
) -> dict:
    text = WORKFLOW.read_text(encoding="utf-8")
    queue = text.split("  queue_watchdog:\n", 1)[1]
    budget = re.search(r'STALL_AFTER_SECONDS: "(\d+)"', queue)
    assert budget is not None
    node = shutil.which("node")
    assert node, "Node.js is required to execute the actual workflow JavaScript; do not skip."
    payload = {
        "source": observer_source(text), "start_ms": START_MS,
        "workflow_age_ms": workflow_age_ms, "pickup_after_ms": pickup_after_ms,
        "stall_seconds": budget.group(1), "job_name": JOB_NAME,
        "expected_runner": expected_runner,
        "queued_job": job(), "final_job": final_job,
    }
    with tempfile.TemporaryDirectory(prefix="dedicated-watchdog-test-") as directory:
        harness = Path(directory) / "observer-harness.cjs"
        harness.write_text(NODE_HARNESS, encoding="utf-8")
        result = subprocess.run(
            [node, str(harness)], input=json.dumps(payload),
            text=True, capture_output=True, timeout=10, check=False,
        )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_budget_is_300_seconds_with_time_for_setup_and_final_gate() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    queue = text.split("  queue_watchdog:\n", 1)[1]
    assert 'STALL_AFTER_SECONDS: "300"' in queue
    assert int(re.search(r"timeout-minutes: (\d+)", queue).group(1)) >= 7
    assert "const anchor = new Date();" in observer_source(text)
    assert "run.data.created_at" not in observer_source(text)
    assert "if: steps.watchdog.outcome == 'failure'" in queue
    assert "decision.decision !== 'block'" in queue
    assert "cancelWorkflowRun" in queue
    assert "desktop-pdqk954" in text
    assert "--require-runner-version-preflight" in text
    assert "--expected-head" in text


def test_setup_age_does_not_cancel_a_valid_pickup_at_150_seconds() -> None:
    result = observe(job(
        status="in_progress", runner_id=9, runner_name="DESKTOP-PDQK954-runtime",
    ), pickup_after_ms=150_000)
    assert result["elapsed_ms"] == 150_000
    assert result["reads"] > 1
    assert len(result["writes"]) == 1
    assert result["writes"][0]["data"]["state"] == "running"
    assert result["failures"] == result["cancellations"] == []


def test_lenovo_pickup_is_material_progress_only_for_exact_lenovo_runner() -> None:
    result = observe(
        job(status="in_progress", runner_id=24, runner_name="DESKTOP-RP23OGS-runtime"),
        expected_runner="DESKTOP-RP23OGS-runtime",
    )
    assert result["writes"][0]["data"]["state"] == "running"
    assert result["failures"] == result["cancellations"] == []


def test_no_pickup_stops_at_300_seconds_without_refreshing_material_progress() -> None:
    result = observe(job())
    assert result["elapsed_ms"] == 300_000
    assert result["reads"] == 21
    assert len(result["writes"]) == 1
    record = result["writes"][0]["data"]
    assert record["state"] == "queued"
    assert record["last_material_progress_at"] == "2026-10-15T14:00:00.000Z"
    assert record["last_observation_at"] == "2026-10-15T14:05:00.000Z"


@pytest.mark.parametrize("not_a_pickup", [
    job(status="waiting"),
    job(status="completed", conclusion="skipped"),
    job(status="in_progress", runner_id=9, runner_name="DESKTOP-RP23OGS-runtime"),
    job(status="in_progress", run_id=76, runner_id=9, runner_name="DESKTOP-PDQK954-runtime"),
    job(status="queued", runner_id=9, runner_name="DESKTOP-PDQK954-runtime"),
])
def test_status_change_wrong_host_or_wrong_run_cannot_fake_pickup(not_a_pickup: dict) -> None:
    result = observe(not_a_pickup)
    assert result["elapsed_ms"] == 300_000
    assert result["writes"][0]["data"]["state"] == "queued"


def test_replay_has_the_same_decision_and_one_receipt_per_observation() -> None:
    first = observe(job())
    second = observe(job())
    assert first == second
    assert len(first["writes"]) == 1
    assert first["cancellations"] == []
