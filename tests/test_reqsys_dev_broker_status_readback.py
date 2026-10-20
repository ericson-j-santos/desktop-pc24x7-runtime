"""Controls for request correlation, privacy, replay and unchanged admission."""
from copy import deepcopy
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pr71_broker_status_readback", ROOT / "scripts/reqsys_dev_broker_status_readback.py"
)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
ISSUED = "2026-10-15T14:46:36Z"
NOW = "2026-10-15T14:51:36Z"
COMMENT = 6194882471


def evidence():
    return {
        "comment_id": COMMENT, "host": m.HOST, "action": "status",
        "status": "completed", "ok": True,
        "result": "DESKTOP_ADMIN_BROKER_READBACK_OBSERVED",
        "trust": "diagnostic_only", "authoritative_success": False,
        "production_touched": False, "secrets_read": False,
        "source_sha": "a" * 40, "broker_generated_at": "2026-10-15T14:50:36Z",
        "result_summary": {"handler": "status"},
    }


def validate(value):
    return m.validate(value, comment_id=COMMENT, issued_at=ISSUED, observed_at=NOW)


def test_positive_is_diagnostic_never_runner_readiness():
    result = validate(evidence())
    assert result["status"] == "observed"
    assert result["comment_id"] == COMMENT
    for key in ("physical_ready", "authoritative_success", "origin_authenticated", "runtime_e2e"):
        assert result[key] is False


@pytest.mark.parametrize("key,value", [
    ("comment_id", COMMENT - 1), ("comment_id", True),
    ("host", "OTHER"), ("action", "recover-runner"), ("status", "failed"),
    ("ok", 1), ("trust", "authoritative"), ("authoritative_success", True),
    ("production_touched", True), ("secrets_read", True),
    ("source_sha", "not-a-sha"), ("broker_generated_at", "invalid"),
    ("broker_generated_at", "2026-10-15T14:45:36Z"),
    ("broker_generated_at", "2026-10-15T14:52:36Z"),
    ("broker_generated_at", "2026-10-15T14:50:36"),
    ("result_summary", {"handler": "recover-runner"}),
])
def test_negative_response_is_rejected(key, value):
    candidate = evidence()
    candidate[key] = value
    with pytest.raises(m.ReadbackError):
        validate(candidate)


def test_repeat_is_deterministic_and_does_not_export_unknown_fields():
    candidate = evidence()
    candidate["secret"] = "MUST_NOT_APPEAR"
    candidate["result_summary"]["url"] = "MUST_NOT_APPEAR"
    first = validate(candidate)
    assert first == validate(deepcopy(candidate))
    assert "MUST_NOT_APPEAR" not in json.dumps(first)


def env():
    return {"GITHUB_SHA": "b" * 40, "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "1", "EXPECTED_COMMENT_ID": str(COMMENT),
            "EXPECTED_ISSUED_AT": ISSUED}


def test_execute_and_independent_file_readback(tmp_path):
    target = tmp_path / "evidence.json"
    calls = []
    def reader():
        calls.append(1)
        return evidence()
    result = m.execute(env(), reader=reader, observed_at=NOW, output=target)
    assert json.loads(target.read_text()) == result
    assert result["source_runtime_sha"] == "b" * 40
    assert result["run_id"] == "1234"
    assert calls == [1]


@pytest.mark.parametrize("key,value", [
    ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_SHA", "bad"),
    ("GITHUB_RUN_ID", "0"), ("EXPECTED_COMMENT_ID", "-1"),
    ("EXPECTED_ISSUED_AT", "2026-10-15T13:00:00Z"),
])
def test_invalid_precondition_never_calls_transport(tmp_path, key, value):
    config = env()
    config[key] = value
    calls = []
    result = m.execute(config, reader=lambda: calls.append(1),
                       observed_at=NOW, output=tmp_path / "evidence.json")
    assert result["status"] == "blocked"
    assert not calls


def test_transport_failure_is_sanitized_and_overwrites_old_success(tmp_path):
    target = tmp_path / "evidence.json"
    m.execute(env(), reader=evidence, observed_at=NOW, output=target)
    def failed():
        raise OSError("MUST_NOT_APPEAR")
    result = m.execute(env(), reader=failed, observed_at=NOW, output=target)
    assert result["status"] == "blocked"
    assert "MUST_NOT_APPEAR" not in target.read_text()
    assert json.loads(target.read_text()) == result


def diagnostic_source():
    return (ROOT / ".github/workflows/reqsys-dev-broker-status-readback.yml").read_text().replace("\r\n", "\n")


def test_workflow_preserves_independent_physical_gate():
    source = (ROOT / ".github/workflows/reqsys-dev-readonly-inventory.yml").read_text()
    source = source.replace("\r\n", "\n")
    assert "python -m pytest -q tests/test_reqsys_dev_broker_status_readback.py" in source
    assert "      - .github/workflows/reqsys-dev-broker-status-readback.yml\n" in source
    assert "  broker_readback:\n" not in source
    assert "  admission:\n    needs: contract\n" in source
    assert source.count("needs.admission.outputs.physical_ready == 'true'") == 2
    assert "EXPECTED_COMMENT_ID:" not in source
    assert "EXPECTED_ISSUED_AT:" not in source
    broker = diagnostic_source()
    assert "on:\n  workflow_dispatch:\n    inputs:\n      comment_id:\n" in broker
    assert "        required: true\n" in broker
    assert "EXPECTED_COMMENT_ID: ${{ inputs.comment_id }}" in broker
    assert "EXPECTED_ISSUED_AT: ${{ steps.request.outputs.issued_at }}" in broker
    assert "permissions:\n  contents: read\n  issues: read\n" in broker
    assert "runs-on: ubuntu-latest" in broker
    assert "continue-on-error" not in broker
    assert "include-hidden-files: true" in broker
    assert "always() && steps.readback.outcome != 'skipped'" in broker
    for forbidden in ("6194882471", "2026-10-15T14:46:36Z", "self-hosted",
                      "createWorkflowDispatch", "actions: write",
                      "physical_ready", "  push:", "  schedule:"):
        assert forbidden not in broker


def owner_request():
    return {
        "id": COMMENT, "user": {"login": "ericson-j-santos"},
        "author_association": "OWNER", "body": "/desktop-runtime admin status",
        "created_at": ISSUED, "updated_at": ISSUED,
        "issue_url": "https://api.github.com/repos/ericson-j-santos/desktop-pc24x7-runtime/issues/2",
    }


def run_owner_verifier(comment, *, comment_id=None, event="workflow_dispatch",
                       owner="ericson-j-santos", repo="desktop-pc24x7-runtime",
                       attempt="1", api_error=False, observed_at=NOW):
    """Execute the workflow's exact JS with a bounded, offline API fixture."""
    source = diagnostic_source()
    block = source.split("          script: |\n", 1)[1].split("      - name: Read fixed diagnostic", 1)[0]
    script = "\n".join(line[12:] for line in block.rstrip().splitlines())
    payload = {
        "comment": comment, "comment_id": str(COMMENT) if comment_id is None else comment_id,
        "event": event, "owner": owner, "repo": repo, "attempt": attempt,
        "api_error": api_error, "observed_at": observed_at,
    }
    harness = r"""
const fs = require('node:fs');
const value = JSON.parse(fs.readFileSync(0, 'utf8'));
const outputs = {}, failures = [], calls = [];
const context = {repo: {owner: value.owner, repo: value.repo}, eventName: value.event};
const core = {setFailed: x => failures.push(x), setOutput: (k,v) => { outputs[k] = v; }};
const github = {rest: {issues: {getComment: async args => {
  calls.push(args);
  if (value.api_error) throw new Error('MUST_NOT_APPEAR');
  return {data: value.comment};
}}}};
process.env.EXPECTED_COMMENT_ID = value.comment_id;
process.env.GITHUB_RUN_ATTEMPT = value.attempt;
Date.now = () => Date.parse(value.observed_at);
(async () => {
""" + script + r"""
})().then(() => console.log(JSON.stringify({outputs, failures, calls})))
.catch(() => { console.error('VERIFIER_TEST_UNEXPECTED_EXCEPTION'); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", harness], input=json.dumps(payload),
        text=True, capture_output=True, check=True, timeout=15,
    )
    assert "MUST_NOT_APPEAR" not in completed.stdout + completed.stderr
    return json.loads(completed.stdout)


def test_owner_verifier_accepts_fresh_exact_request_and_is_deterministic():
    expected = {
        "outputs": {"issued_at": ISSUED}, "failures": [],
        "calls": [{"owner": "ericson-j-santos", "repo": "desktop-pc24x7-runtime",
                   "comment_id": COMMENT}],
    }
    assert run_owner_verifier(owner_request()) == expected
    assert run_owner_verifier(owner_request()) == expected


@pytest.mark.parametrize("changes", [
    {"comment_id": ""}, {"comment_id": "-1"}, {"comment_id": "1.5"},
    {"comment_id": "9007199254740993"}, {"comment_id": "1;MUST_NOT_APPEAR"},
    {"event": "push"}, {"owner": "OTHER"}, {"repo": "OTHER"}, {"attempt": "2"},
])
def test_owner_verifier_invalid_scope_never_calls_api(changes):
    result = run_owner_verifier(owner_request(), **changes)
    assert result == {"outputs": {}, "failures": ["BROKER_REQUEST_SCOPE_INVALID"], "calls": []}


@pytest.mark.parametrize("changes", [
    {"id": COMMENT - 1}, {"user": {"login": "OTHER"}},
    {"author_association": "MEMBER"}, {"body": "/desktop-runtime admin recover-runner"},
    {"updated_at": "2026-10-15T14:47:36Z"}, {"issue_url": "https://example.invalid/issues/2"},
    {"created_at": "invalid", "updated_at": "invalid"},
    {"created_at": "2026-10-15T13:00:00Z", "updated_at": "2026-10-15T13:00:00Z"},
    {"created_at": "2026-10-15T14:52:36Z", "updated_at": "2026-10-15T14:52:36Z"},
])
def test_owner_verifier_rejects_tampered_expired_or_future_request(changes):
    candidate = owner_request()
    candidate.update(changes)
    result = run_owner_verifier(candidate)
    assert result["outputs"] == {}
    assert len(result["failures"]) == 1
    assert len(result["calls"]) == 1


def test_owner_verifier_api_failure_is_sanitized():
    result = run_owner_verifier(owner_request(), api_error=True)
    assert result["outputs"] == {}
    assert result["failures"] == ["BROKER_OWNER_REQUEST_READBACK_UNAVAILABLE"]


def test_historical_workflow_request_is_expired_before_any_diagnostic_read(tmp_path):
    calls = []
    result = m.execute(env(), reader=lambda: calls.append(1),
                       observed_at="2026-10-15T19:43:10Z",
                       output=tmp_path / "evidence.json")
    assert result["status"] == "blocked"
    assert result["reason"] == "BROKER_REQUEST_EXPIRED_OR_FUTURE"
    assert not calls


def test_observation_clock_is_taken_after_transport(monkeypatch, tmp_path):
    original_datetime = m.datetime
    moments = iter(["2026-10-15T14:49:36+00:00", "2026-10-15T14:51:36+00:00"])
    class Clock(original_datetime):
        @classmethod
        def now(cls, tz=None):
            return original_datetime.fromisoformat(next(moments))
    monkeypatch.setattr(m, "datetime", Clock)
    result = m.execute(env(), reader=evidence, output=tmp_path / "evidence.json")
    assert result["status"] == "observed"
    assert result["observed_at"] == "2026-10-15T14:51:36+00:00"
