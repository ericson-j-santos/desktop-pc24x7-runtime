"""Fail-closed contracts for the real issue-8 Qwen7B physical stage.

Fixtures test only bounded public bundle receipts and output IPC. They do not
simulate physical inference, a durable CAS write or a Worker Pool shared lease.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from scripts import issue8_qwen7b_fenced_bundle_stage as stage


def valid():
    raw = b"# public immutable Git bundle sample\n" * 12
    return {
        "result": "ISSUE8_BUNDLE_STAGED_UNPUBLISHED",
        "issue": stage.ISSUE,
        "source_repository": stage.WORKER,
        "base_sha": stage.WORKER_SHA,
        "produced_sha": "f" * 40,
        "worker_pool_task_id": "cwp-" + "a" * 24,
        "owner_comment_id": stage.OWNER_COMMENT,
        "correlation_id": "qwen7b-issue-8-" + stage.WORKER_SHA[:12],
        "model": stage.MODEL,
        "model_digest": stage.MODEL_PREFIX + "a" * (64 - len(stage.MODEL_PREFIX)),
        "model_calls": 1,
        "replay_model_calls": 0,
        "before_sha256": "b" * 64,
        "after_sha256": "c" * 64,
        "patch_sha256": "d" * 64,
        "bundle_sha256": hashlib.sha256(raw).hexdigest(),
        "bundle_b64": base64.b64encode(raw).decode("ascii"),
        "baseline_passed": 26,
        "accepted_cases": 42,
        "regressions_passed": 52,
        "independent_checkout": True,
        "lease_generation": 1,
        "fencing_required": True,
        "local_authority_only": True,
        "cas_persisted": False,
        "pr_created": False,
    }


def test_valid_receipt_is_only_staged_and_cannot_claim_ready_for_pr():
    receipt = stage.verified_bundle_receipt(valid())
    assert receipt["bundle_bytes"] > 200
    assert receipt["cas_persisted"] is False
    assert receipt["pr_created"] is False
    assert receipt["local_authority_only"] is True
    assert receipt["replay_model_calls"] == 0


@pytest.mark.parametrize(("field", "value"), [
    ("issue", 9),
    ("base_sha", "0" * 40),
    ("produced_sha", stage.WORKER_SHA),
    ("produced_sha", "not-a-commit"),
    ("owner_comment_id", 1),
    ("worker_pool_task_id", "bad"),
    ("model", "some-cloud-model"),
    ("model_digest", "f" * 64),
    ("model_calls", 0),
    ("model_calls", 3),
    ("replay_model_calls", 1),
    ("baseline_passed", 42),
    ("accepted_cases", 41),
    ("regressions_passed", 51),
    ("independent_checkout", False),
    ("lease_generation", 0),
    ("fencing_required", False),
    ("local_authority_only", False),
    ("cas_persisted", True),
    ("pr_created", True),
])
def test_fake_success_and_out_of_scope_are_rejected(field, value):
    receipt = valid()
    receipt[field] = value
    with pytest.raises(stage.IssueStageBlocked):
        stage.verified_bundle_receipt(receipt)


@pytest.mark.parametrize("change", [
    "missing",
    "invalid-base64",
    "bad-digest",
    "large-bundle",
    "empty-bundle",
])
def test_bytes_cannot_be_forged(change):
    receipt = valid()
    if change == "missing":
        del receipt["bundle_b64"]
    elif change == "invalid-base64":
        receipt["bundle_b64"] = "not a base64 value!!!"
    elif change == "bad-digest":
        receipt["bundle_sha256"] = "f" * 64
    elif change == "large-bundle":
        receipt["bundle_b64"] = base64.b64encode(b"x" * 96001).decode()
    elif change == "empty-bundle":
        receipt["bundle_b64"] = ""
    with pytest.raises(stage.IssueStageBlocked):
        stage.verified_bundle_receipt(receipt)


def test_safe_github_output_only_after_validation(monkeypatch, tmp_path):
    report = valid()
    temp = tmp_path / "runner_temp"
    commands = temp / "_runner_file_commands"
    commands.mkdir(parents=True)
    dest = commands / "set_output_001"
    dest.write_text("", encoding="ascii")
    monkeypatch.setenv("RUNNER_TEMP", str(temp))
    monkeypatch.setenv("GITHUB_OUTPUT", str(dest))
    stage._publish_github_step_outputs(report)
    actual = dest.read_text("ascii")
    assert actual.count("\n") == 2
    entries = dict(line.split("=", 1) for line in actual.splitlines())
    assert base64.b64decode(entries["bundle_b64"]) == base64.b64decode(report["bundle_b64"])
    assert entries["receipt_b64"] != report["bundle_b64"]
    source_receipt = __import__("json").loads(base64.b64decode(entries["receipt_b64"]))
    assert source_receipt["produced_sha"] == report["produced_sha"]
    assert source_receipt["cas_persisted"] is False
    assert "bundle_b64" not in source_receipt


def test_reject_nonrunner_output_path_without_side_effect(monkeypatch, tmp_path):
    report = valid()
    temp = tmp_path / "temp"
    temp.mkdir()
    outside = tmp_path / "foreign"
    outside.write_text("intact", encoding="ascii")
    monkeypatch.setenv("RUNNER_TEMP", str(temp))
    monkeypatch.setenv("GITHUB_OUTPUT", str(outside))
    with pytest.raises(stage.IssueStageBlocked, match="github_output_destination_untrusted"):
        stage._publish_github_step_outputs(report)
    assert outside.read_text("ascii") == "intact"


def test_model_entry_has_real_issue_fenced_pool_and_uses_no_github_write():
    source = (Path(__file__).resolve().parents[1] /
              "scripts/issue8_qwen7b_fenced_bundle_stage.py").read_text("utf8")
    for required in (
        "WorkerPoolStore(", "fencing_required=True",
        "pool.claim_task(", "pool.start_task(", "NativeStructuredOllama()",
        "replay_model_calls", "run_bridge_regressions(independent, sandbox)",
        "git(builder, \"bundle\", \"create\"",
        "git(worker, \"bundle\", \"verify\"",
        "source_integrity_lost",
    ):
        assert required in source
    for forbidden in ("docker run", "docker compose", "git push",
                      "force-with-lease", "gh pr merge", "ollama pull",
                      "repo.create_pull_request", "https://api.openai.com"):
        assert forbidden not in source.lower()
