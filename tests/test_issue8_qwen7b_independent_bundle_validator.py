"""Independent validation boundary: adversarial receipts and fake bundle bytes.

No test fixture substitutes for the pending GitHub-hosted Git bundle E2E.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts import issue8_qwen7b_independent_bundle_validator as validator


def valid():
    raw = b"Git bundle test bytes" * 20
    return {
        "result": "ISSUE8_BUNDLE_STAGED_UNPUBLISHED",
        "issue": 8,
        "source_repository": "ericson-j-santos/engineering-worker-pool",
        "base_sha": validator.BASE,
        "owner_comment_id": 6399359287,
        "worker_pool_task_id": "cwp-" + "a" * 24,
        "produced_sha": "f" * 40,
        "model": "qwen2.5-coder:7b",
        "model_digest": "dae161e27b0e" + "a" * 52,
        "model_calls": 1,
        "replay_model_calls": 0,
        "independent_checkout": True,
        "fencing_required": True,
        "local_authority_only": True,
        "cas_persisted": False,
        "pr_created": False,
        "baseline_passed": 26,
        "accepted_cases": 42,
        "regressions_passed": 52,
        "before_sha256": "1" * 64,
        "after_sha256": "2" * 64,
        "patch_sha256": "3" * 64,
        "bundle_sha256": hashlib.sha256(raw).hexdigest(),
    }, raw


def test_receipt_control_positive_only_authenticates_shape_and_bundle():
    receipt, blob = valid()
    validator.validate_receipt(receipt, blob)
    assert receipt["cas_persisted"] is False
    assert receipt["pr_created"] is False


@pytest.mark.parametrize(("field", "value"), [
    ("result", "READY_FOR_PR"),
    ("base_sha", "e" * 40),
    ("produced_sha", validator.BASE),
    ("owner_comment_id", 1),
    ("model", "remote-model"),
    ("model_digest", "f" * 64),
    ("model_calls", 0),
    ("model_calls", 3),
    ("replay_model_calls", 1),
    ("fencing_required", False),
    ("local_authority_only", False),
    ("cas_persisted", True),
    ("pr_created", True),
    ("independent_checkout", False),
    ("baseline_passed", 42),
    ("accepted_cases", 41),
    ("regressions_passed", 51),
    ("worker_pool_task_id", "wrong"),
])
def test_unsafe_receipts_fail_closed(field, value):
    receipt, blob = valid()
    receipt[field] = value
    with pytest.raises(validator.ValidationBlocked):
        validator.validate_receipt(receipt, blob)


def test_tampered_bundle_is_rejected():
    receipt, blob = valid()
    with pytest.raises(validator.ValidationBlocked, match="validator_bundle_digest_invalid"):
        validator.validate_receipt(receipt, blob + b"tampered")


def test_git_checkout_and_exact_files_are_required_by_real_validator():
    text = (Path(__file__).resolve().parents[1] /
            "scripts/issue8_qwen7b_independent_bundle_validator.py").read_text("utf8")
    for symbol in ("bundle\", \"verify", "fetch\", \"--no-tags",
                   "rev-list\", \"--parents", "rev-list\", \"--count",
                   "run_bridge_regressions(independent, root)",
                   "git(source_root, \"rev-parse\", \"HEAD\") == BASE",
                   "\"ready_for_pr\": False"):
        assert symbol in text
    assert "git push" not in text.lower()
    assert "gh pr merge" not in text.lower()
