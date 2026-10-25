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
        'git(sandbox, "-c", "core.autocrlf=false", "clone"',
        "pool.claim_task(", "pool.start_task(", "NativeStructuredOllama()",
        "replay_model_calls", "run_bridge_regressions(independent, sandbox)",
        "git(builder, \"bundle\", \"create\"",
        "git(worker, \"bundle\", \"verify\"",
        "verified_final_checkouts",
        "source_raw_bytes_changed",
        "source_index_changed",
        'prefix + "_checkout_dirty"',
    ):
        assert required in source
    for forbidden in ("docker run", "docker compose", "git push",
                      "force-with-lease", "gh pr merge", "ollama pull",
                      "repo.create_pull_request", "https://api.openai.com"):
        assert forbidden not in source.lower()


def _isolated_final_integrity_fixture(tmp_path):
    """Pure unit fixture: no physical inference, CAS, credential or GitHub write."""
    worker = tmp_path / "source"
    source_file = worker / stage.PATH
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(b"unmodified LF source\n")
    builder = tmp_path / "builder"
    independent = tmp_path / "validator"
    builder.mkdir()
    independent.mkdir()
    produced = "e" * 40
    state = {
        "source_head": stage.WORKER_SHA,
        "source_index": "",
        "source_mode": "exact_clean",
        "source_clean_error": "",
        "builder_head": produced,
        "builder_status": "",
        "validator_head": produced,
        "validator_status": "",
    }
    observed = []

    def git_read(root, *arguments):
        observed.append((root, arguments))
        if root == worker and arguments == ("rev-parse", "HEAD"):
            return state["source_head"]
        if root == worker and arguments == (
                "diff", "--cached", "--name-only", "HEAD", "--"):
            return state["source_index"]
        for name, checkout in (("builder", builder), ("validator", independent)):
            if root == checkout and arguments == ("rev-parse", "HEAD"):
                return state[name + "_head"]
            if root == checkout and arguments == (
                    "status", "--porcelain", "--untracked-files=all"):
                return state[name + "_status"]
        raise AssertionError("unexpected Git operation")

    def source_clean(root):
        assert root == worker
        if state["source_clean_error"]:
            raise RuntimeError(state["source_clean_error"])
        return state["source_mode"]

    values = {
        "source_raw_sha256": hashlib.sha256(source_file.read_bytes()).hexdigest(),
        "produced_sha": produced,
        "git_read": git_read,
        "source_clean": source_clean,
    }
    return worker, builder, independent, source_file, state, observed, values


def test_final_integrity_accepts_git_mode_transition_and_idempotent_replay(tmp_path):
    worker, builder, independent, source_file, state, commands, values = (
        _isolated_final_integrity_fixture(tmp_path)
    )
    # Git's status label can change after stat refresh without byte changes.
    state["source_mode"] = "git_verified_crlf_normalization"
    assert values["source_clean"](worker) == "git_verified_crlf_normalization"
    state["source_mode"] = "exact_clean"
    for _ in range(2):
        stage.verified_final_checkouts(worker, builder, independent, **values)
    assert source_file.read_bytes() == b"unmodified LF source\n"
    assert all(command[1][0] in {"rev-parse", "diff", "status"}
               for command in commands)


@pytest.mark.parametrize(("fault", "reason"), [
    ("source_head", "source_head_changed"),
    ("source_bytes", "source_raw_bytes_changed"),
    ("source_crlf", "source_raw_bytes_changed"),
    ("source_index", "source_index_changed"),
    ("source_tree", "source_tree_dirty"),
    ("source_blob", "source_blob_mismatch"),
    ("source_unverified", "source_checkout_unverified"),
    ("source_mode_unknown", "source_checkout_unverified"),
    ("builder_head", "builder_head_changed"),
    ("builder_status", "builder_checkout_dirty"),
    ("validator_head", "validator_head_changed"),
    ("validator_status", "validator_checkout_dirty"),
])
def test_final_integrity_rejects_real_drift_and_identifies_gate(tmp_path, fault, reason):
    worker, builder, independent, source_file, state, _, values = (
        _isolated_final_integrity_fixture(tmp_path)
    )
    if fault == "source_head":
        state["source_head"] = "f" * 40
    elif fault == "source_bytes":
        source_file.write_bytes(b"changed content\n")
    elif fault == "source_crlf":
        source_file.write_bytes(b"unmodified LF source\r\n")
    elif fault == "source_index":
        state["source_index"] = stage.PATH
    elif fault == "source_tree":
        state["source_clean_error"] = "source_tree_dirty"
    elif fault == "source_blob":
        state["source_clean_error"] = "source_blob_mismatch"
    elif fault == "source_unverified":
        state["source_clean_error"] = "unexpected failure"
    elif fault == "source_mode_unknown":
        state["source_mode"] = "unchecked"
    elif fault == "builder_head":
        state["builder_head"] = "f" * 40
    elif fault == "builder_status":
        state["builder_status"] = "?? unexpected.tmp"
    elif fault == "validator_head":
        state["validator_head"] = "f" * 40
    elif fault == "validator_status":
        state["validator_status"] = " M app/portfolio_bridge.py"
    with pytest.raises(stage.IssueStageBlocked, match="^" + reason + "$"):
        stage.verified_final_checkouts(worker, builder, independent, **values)
