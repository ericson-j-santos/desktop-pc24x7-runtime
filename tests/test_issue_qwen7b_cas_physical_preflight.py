"""Pure physical CAS preflight admission controls, no live host or token."""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts.issue_qwen7b_cas_physical_preflight import (
    BASE_SHA, PreflightBlocked, gate_preflight,
)

PIN = "dae161e27b0e"
MODEL_DIGEST = PIN + "a" * (64 - len(PIN))


def valid_values():
    issue = {
        "issue": 8, "base_sha": BASE_SHA, "owner_verified": True,
        "baseline_passed": 26, "cases_total": 42,
        "source_sha256": "d" * 64,
    }
    model = {
        "model": "qwen2.5-coder:7b", "digest": MODEL_DIGEST,
        "local_only": True, "model_calls": 0,
    }
    cas = {
        "sha256_verified": True, "issue_scoped": True,
        "branch_sha": "e" * 40, "object_sha256": "f" * 64,
    }
    return issue, model, cas


def harness(issue=None, model=None, cas=None):
    source, local, evidence = valid_values()
    source = issue if issue is not None else source
    local = model if model is not None else local
    evidence = cas if cas is not None else evidence
    calls = []

    def issue_checked():
        calls.append("issue")
        return source

    def model_checked():
        calls.append("model")
        return local

    def persist():
        calls.append("cas-write")

    def readback():
        calls.append("cas-readback")
        return evidence

    return calls, {
        "issue_result": issue_checked, "model_result": model_checked,
        "cas_preflight": persist, "cas_readback": readback,
    }


def test_cas_preflight_orders_issue_and_model_before_external_write():
    calls, dependencies = harness()
    result = gate_preflight(**dependencies)
    assert calls == ["issue", "model", "cas-write", "cas-readback"]
    assert result["result"] == "ISSUE_QWEN7B_CAS_PREFLIGHT_PASSED"
    assert result["issue"] == 8
    assert result["baseline_passed"] == 26
    assert result["model_calls"] == 0
    assert result["cas_independent_readback"] is True
    assert result["pr_created"] is False
    assert result["production_touched"] is False


@pytest.mark.parametrize(("changed", "value"), [
    ("issue", 9), ("owner_verified", False),
    ("base_sha", "f" * 40),
    ("baseline_passed", 42), ("cases_total", 41),
    ("source_sha256", "BAD"),
])
def test_invalid_issue_or_baseline_never_calls_model_or_cas(changed, value):
    issue, _, _ = valid_values()
    issue[changed] = value
    calls, deps = harness(issue=issue)
    with pytest.raises(PreflightBlocked, match="issue_authorization_or_baseline_missing"):
        gate_preflight(**deps)
    assert calls == ["issue"]


@pytest.mark.parametrize(("changed", "value"), [
    ("model", "remote-provider"), ("digest", "a" * 64),
    ("local_only", False), ("model_calls", 1),
])
def test_invalid_local_model_never_writes_cas(changed, value):
    _, model, _ = valid_values()
    model[changed] = value
    calls, deps = harness(model=model)
    with pytest.raises(PreflightBlocked, match="local_qwen_readiness_unproved"):
        gate_preflight(**deps)
    assert calls == ["issue", "model"]


@pytest.mark.parametrize(("changed", "value"), [
    ("sha256_verified", False), ("issue_scoped", False),
    ("branch_sha", BASE_SHA), ("branch_sha", "invalid"),
    ("object_sha256", "BAD"),
])
def test_false_cas_readback_never_approves(changed, value):
    _, _, cas = valid_values()
    cas[changed] = value
    calls, deps = harness(cas=cas)
    with pytest.raises(PreflightBlocked, match="remote_cas_readback_unproved"):
        gate_preflight(**deps)
    assert calls == ["issue", "model", "cas-write", "cas-readback"]


def test_cas_transport_failure_cannot_become_success():
    calls, deps = harness()
    def fails():
        calls.append("cas-write")
        raise PreflightBlocked("artifact_store_unavailable")
    deps["cas_preflight"] = fails
    with pytest.raises(PreflightBlocked, match="artifact_store_unavailable"):
        gate_preflight(**deps)
    assert calls == ["issue", "model", "cas-write"]


def test_preflight_has_no_merge_or_model_generation_path():
    source = (
        Path(__file__).resolve().parents[1]
        / "scripts" / "issue_qwen7b_cas_physical_preflight.py"
    ).read_text(encoding="utf-8")
    assert "governed_bundle_transport" in source
    assert "verified_source_clean" in source
    assert "PORTFOLIO_GITHUB_TOKEN_FILE" in source
    assert "NativeStructuredOllama" in source
    assert "port.get_comment(OWNER_COMMENT_ID)" in source
    assert 'model_calls": 0' in source
    assert "docker run" not in source.lower()
    assert "git push" not in source.lower()
    assert "ollama pull" not in source.lower()
