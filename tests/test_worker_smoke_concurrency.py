"""Exercise the workflow group expression with synthetic GitHub contexts.

Only the string/boolean operator subset used here is evaluated in a Node sandbox.
This is not a live GitHub scheduler or a physical Desktop E2E test.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github/workflows/engineering-worker-pool-smoke-dev.yml"
)
CANONICAL_GROUP = "engineering-worker-pool-smoke-dev"
REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
GATE = (
    "github.event_name != 'pull_request' || "
    "(!github.event.pull_request.draft && "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)
TOKEN = re.compile(
    r"\s+|'[^'\\]*'|github\.(?:event\.pull_request\.head\.repo\.full_name"
    r"|event\.pull_request\.draft|event_name|repository|run_id)"
    r"|format|!=|==|&&|\|\||[!(),]"
)
HARNESS = r"""
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const groups = input.contexts.map(github => vm.runInNewContext(input.source, {
  github,
  format: (template, value) => template.replace('{0}', String(value)),
}, {timeout: 1000}));
process.stdout.write(JSON.stringify(groups));
"""


def group_source(raw: str) -> str:
    header = raw.split("\njobs:\n", 1)[0]
    groups = re.findall(r"^  group: (.+)$", header, re.MULTILINE)
    assert len(groups) == 1, "Exactly one workflow concurrency group is required"
    value = groups[0].strip()
    if not value.startswith("${{"):
        return json.dumps(value)
    assert value.endswith("}}"), "Malformed GitHub expression"
    source = value[3:-2].strip()
    position = 0
    while position < len(source):
        match = TOKEN.match(source, position)
        assert match, "Expression is outside the bounded test grammar"
        position = match.end()
    return source


def context(event: str, *, draft: bool = False, fork: bool = False, run: int = 100) -> dict:
    event_data = {}
    if event == "pull_request":
        event_data["pull_request"] = {
            "draft": draft,
            "head": {"repo": {"full_name": "untrusted/fork" if fork else REPOSITORY}},
        }
    return {"event_name": event, "event": event_data, "repository": REPOSITORY, "run_id": run}


def groups_for(*contexts: dict, raw: str | None = None) -> list[str]:
    text = WORKFLOW.read_text(encoding="utf-8") if raw is None else raw
    node = shutil.which("node")
    assert node, "Node.js is required for expression regression tests; do not skip"
    payload = {"source": group_source(text), "contexts": contexts}
    with tempfile.TemporaryDirectory(prefix="smoke-group-test-") as directory:
        harness = Path(directory) / "group.cjs"
        harness.write_text(HARNESS, encoding="utf-8")
        result = subprocess.run(
            [node, str(harness)], input=json.dumps(payload), text=True,
            capture_output=True, timeout=10, check=False,
        )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("event", ["push", "workflow_dispatch", "schedule"])
def test_non_pr_runs_keep_existing_global_group_without_pr_context(event: str) -> None:
    assert groups_for(context(event)) == [CANONICAL_GROUP]


def test_admitted_prs_keep_same_global_serialization_as_main() -> None:
    assert groups_for(
        context("push"), context("pull_request", run=101), context("pull_request", run=102),
    ) == [CANONICAL_GROUP] * 3


@pytest.mark.parametrize(("draft", "fork"), [(True, False), (False, True), (True, True)])
def test_unadmitted_pr_cannot_cancel_or_replace_main_group(draft: bool, fork: bool) -> None:
    main_group, rejected_group = groups_for(
        context("push"), context("pull_request", draft=draft, fork=fork, run=101),
    )
    assert main_group == CANONICAL_GROUP
    assert rejected_group == CANONICAL_GROUP + "-unadmitted-101"
    assert rejected_group != main_group


def test_replay_is_stable_and_distinct_unadmitted_runs_do_not_collide() -> None:
    first = context("pull_request", draft=True, run=101)
    second = context("pull_request", draft=True, run=102)
    a, replay, b = groups_for(first, first, second)
    assert a == replay
    assert a != b


def test_job_gates_dependencies_and_cancellation_policy_remain() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    header, jobs = text.split("\njobs:\n", 1)
    assert f"({GATE}) && '{CANONICAL_GROUP}'" in group_source(text)
    assert "  cancel-in-progress: true" in header
    assert jobs.count("    if: " + GATE) == 3
    assert "    needs: prepare_runner" in jobs
    assert "SESSION_LAUNCH_OK" in jobs
    assert "command_gateway.py" in jobs
    assert "--expected-head" in jobs


@pytest.mark.parametrize("fault", ["global", "no-draft-check", "no-fork-check", "renamed-active"])
def test_negative_control_detects_unsafe_group_regressions(fault: str) -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    header, jobs = text.split("\njobs:\n", 1)
    if fault == "global":
        header = re.sub(r"(?m)^  group: .+$", "  group: " + CANONICAL_GROUP, header)
    elif fault == "no-draft-check":
        header = header.replace("!github.event.pull_request.draft && ", "")
    elif fault == "no-fork-check":
        header = header.replace(
            " && github.event.pull_request.head.repo.full_name == github.repository", "",
        )
    else:
        header = header.replace("&& '" + CANONICAL_GROUP + "'", "&& 'parallel-active-group'")
    mutated = header + "\njobs:\n" + jobs
    actual = groups_for(
        context("push"), context("pull_request"),
        context("pull_request", draft=True, run=101),
        context("pull_request", fork=True, run=102),
        raw=mutated,
    )
    expected = [
        CANONICAL_GROUP, CANONICAL_GROUP,
        CANONICAL_GROUP + "-unadmitted-101", CANONICAL_GROUP + "-unadmitted-102",
    ]
    assert actual != expected, "The regression harness failed to detect the unsafe mutation"
