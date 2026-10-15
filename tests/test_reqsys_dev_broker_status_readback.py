"""Controls for request correlation, privacy, replay and unchanged admission."""
from copy import deepcopy
import importlib.util
import json
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


def test_workflow_preserves_independent_physical_gate():
    source = (ROOT / ".github/workflows/reqsys-dev-readonly-inventory.yml").read_text()
    source = source.replace("\r\n", "\n")
    assert "python -m pytest -q tests/test_reqsys_dev_broker_status_readback.py" in source
    assert "  broker_readback:\n    needs: contract\n" in source
    assert "  admission:\n    needs: contract\n" in source
    assert source.count("needs.admission.outputs.physical_ready == 'true'") == 2
    broker = source.split("  broker_readback:\n", 1)[1].split("  admission:\n", 1)[0]
    assert "runs-on: ubuntu-latest" in broker
    assert "continue-on-error" not in broker
    assert "EXPECTED_COMMENT_ID: '6194882471'" in broker
    assert "include-hidden-files: true" in broker
    assert "context.runAttempt" not in broker  # identity validated by the Python entrypoint

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
