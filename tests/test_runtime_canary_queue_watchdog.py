"""Execute the runtime-canary inline pickup observer with simulated GitHub/time."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/runtime-canary.yml"
START_MS = 1792494000000
JOB_NAME = "Runner, Docker and workers canary"
RUNNER = "DESKTOP-PDQK954-runtime"

NODE_HARNESS = r"""
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let clock = input.start_ms, reads = 0;
const writes = [], failures = [];
class TestDate extends Date {
  constructor(...args) { super(...(args.length ? args : [clock])); }
  static now() { return clock; }
}
const github = {rest: {actions: {
  listJobsForWorkflowRun: async () => {
    if (++reads > 50) throw new Error('OBSERVER_DID_NOT_STOP');
    const job = clock - input.start_ms >= input.pickup_after_ms
      ? input.final_job : input.queued_job;
    return {data: {jobs: [job]}};
  },
}}};
const sandbox = {
  github,
  context: {repo: {owner: 'ericson-j-santos', repo: 'desktop-pc24x7-runtime'}},
  core: {setFailed: reason => failures.push(reason)},
  process: {env: {
    STALL_AFTER_SECONDS: input.stall_seconds,
    TARGET_RUN_ID: '77',
    TARGET_JOB_NAME: input.job_name,
    EXPECTED_RUNNER: input.runner_name,
    CORRELATION_ID: 'runtime-canary-watchdog-regression',
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
    writes, failures, reads, elapsed_ms: clock - input.start_ms,
  }));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
"""


def observer_source(text: str) -> str:
    marker = "      - name: Observe exact runner pickup without renewing progress\n"
    assert text.count(marker) == 1
    step = text.split(marker, 1)[1].split("\n      - name:", 1)[0]
    source = step.split("          script: |\n", 1)[1]
    lines = source.rstrip().splitlines()
    assert all(line.startswith("            ") or not line.strip() for line in lines)
    return "\n".join(line[12:] for line in lines) + "\n"


def job(**changes: object) -> dict:
    value = {
        "id": 88,
        "name": JOB_NAME,
        "status": "queued",
        "conclusion": None,
        "runner_id": 0,
        "runner_name": "",
        "started_at": None,
    }
    value.update(changes)
    return value


def observe(final_job: dict, *, pickup_after_ms: int = 0) -> dict:
    text = WORKFLOW.read_text(encoding="utf-8")
    queue = text.split("  queue_watchdog:\n", 1)[1]
    budget = re.search(r'STALL_AFTER_SECONDS: "(\d+)"', queue)
    assert budget is not None
    node = shutil.which("node")
    assert node, "Node.js is required to execute the actual workflow JavaScript; do not skip."
    payload = {
        "source": observer_source(text),
        "start_ms": START_MS,
        "pickup_after_ms": pickup_after_ms,
        "stall_seconds": budget.group(1),
        "job_name": JOB_NAME,
        "runner_name": RUNNER,
        "queued_job": job(),
        "final_job": final_job,
    }
    with tempfile.TemporaryDirectory(prefix="runtime-canary-watchdog-test-") as directory:
        harness = Path(directory) / "observer-harness.cjs"
        harness.write_text(NODE_HARNESS, encoding="utf-8")
        result = subprocess.run(
            [node, str(harness)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_budget_starts_at_observation_not_workflow_creation() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    source = observer_source(text)
    assert 'STALL_AFTER_SECONDS: "300"' in text
    assert "const anchor = new Date();" in source
    assert "run.data.created_at" not in source
    assert "last_material_progress_at: anchor.toISOString()" in source


def test_valid_pickup_at_150_seconds_is_material_progress() -> None:
    result = observe(
        job(
            status="in_progress",
            runner_id=9,
            runner_name=RUNNER,
            started_at="2026-10-20T11:02:30Z",
        ),
        pickup_after_ms=150_000,
    )
    assert result["elapsed_ms"] == 150_000
    assert result["reads"] > 1
    assert result["failures"] == []
    assert len(result["writes"]) == 1
    record = result["writes"][0]["data"]
    assert record["state"] == "running"
    assert record["last_material_progress_at"] == record["last_observation_at"]


def test_no_pickup_stops_at_300_seconds_without_poll_refresh() -> None:
    result = observe(job())
    assert result["elapsed_ms"] == 300_000
    assert result["reads"] == 21
    assert result["failures"] == []
    assert len(result["writes"]) == 1
    record = result["writes"][0]["data"]
    assert record["state"] == "queued"
    assert record["last_material_progress_at"] == "2026-10-20T11:00:00.000Z"
    assert record["last_observation_at"] == "2026-10-20T11:05:00.000Z"


@pytest.mark.parametrize(
    "not_a_pickup",
    [
        job(status="waiting"),
        job(status="completed", conclusion="skipped"),
        job(status="in_progress", runner_id=9, runner_name="DESKTOP-RP23OGS-runtime",
            started_at="2026-10-20T11:01:00Z"),
        job(status="queued", runner_id=9, runner_name=RUNNER,
            started_at="2026-10-20T11:01:00Z"),
    ],
)
def test_status_change_or_wrong_runner_cannot_fake_pickup(not_a_pickup: dict) -> None:
    result = observe(not_a_pickup)
    assert result["elapsed_ms"] == 300_000
    assert result["writes"][0]["data"]["state"] == "queued"


def test_replay_produces_same_observation_receipt() -> None:
    first = observe(job())
    second = observe(job())
    assert first == second
    assert len(first["writes"]) == 1

