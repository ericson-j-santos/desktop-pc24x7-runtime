from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "desktop_admin_broker_readback.py"
SPEC = importlib.util.spec_from_file_location("desktop_admin_broker_readback", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_payload_is_diagnostic_only_and_sanitized() -> None:
    accepted = {
        "comment_id": 123,
        "action": "recover-runner",
        "status": "completed",
        "outcome": {
            "result": {
                "handler": "recover-runner",
                "bootstrap_state": "listener_running_pickup_required",
                "runner_running": True,
                "runner_registry_status": "unknown",
                "github_pickup_required": True,
                "ignored_secret": "must-not-leak",
            }
        },
    }

    payload = m.build_payload(
        accepted=accepted,
        source_sha="a" * 40,
        host=m.EXPECTED_HOST,
    )

    raw = json.dumps(payload)
    assert payload["trust"] == "diagnostic_only"
    assert payload["authoritative_success"] is False
    assert payload["result"]["runner_running"] is True
    assert payload["result"]["github_pickup_required"] is True
    assert "ignored_secret" not in raw
    assert "must-not-leak" not in raw


def test_failed_payload_uses_error_code_only() -> None:
    accepted = {
        "comment_id": 456,
        "action": "recover-control-plane",
        "status": "failed",
        "error_code": "BrokerError",
        "error": "raw sensitive detail",
    }

    payload = m.build_payload(
        accepted=accepted,
        source_sha="b" * 40,
        host=m.EXPECTED_HOST,
    )

    raw = json.dumps(payload)
    assert payload["error_code"] == "BrokerError"
    assert "raw sensitive detail" not in raw


def test_wrong_host_and_sha_fail_closed() -> None:
    with pytest.raises(ValueError, match="host_not_allowed"):
        m.build_payload(
            accepted={},
            source_sha="a" * 40,
            host="other-host",
        )
    with pytest.raises(ValueError, match="source_sha_invalid"):
        m.build_payload(
            accepted={},
            source_sha="main",
            host=m.EXPECTED_HOST,
        )


def test_transport_failure_is_non_authoritative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        m.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    result = m.publish_readback(
        accepted={
            "comment_id": 789,
            "action": "recover-runner",
            "status": "failed",
            "error_code": "runner_recovery_failed",
        },
        source_sha="c" * 40,
        host=m.EXPECTED_HOST,
    )
    assert result["published"] is False
    assert result["authoritative"] is False
    assert result["error_code"] == "readback_transport_unavailable"



def test_publish_uses_plain_text_topic_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(m.urllib.request, "urlopen", fake_urlopen)
    result = m.publish_readback(
        accepted={
            "comment_id": 901,
            "action": "status",
            "status": "completed",
            "outcome": {"result": {"handler": "status"}},
        },
        source_sha="d" * 40,
        host=m.EXPECTED_HOST,
        timeout_seconds=3,
    )

    request = captured["request"]
    payload = json.loads(request.data.decode("utf-8"))
    assert request.full_url == m.ENDPOINT
    assert request.headers["Content-type"] == "text/plain; charset=utf-8"
    assert payload["comment_id"] == 901
    assert payload["trust"] == "diagnostic_only"
    assert payload["authoritative_success"] is False
    assert result["published"] is True
    assert result["authoritative"] is False


def test_self_refresh_summary_is_sanitized() -> None:
    accepted = {
        "comment_id": 902,
        "action": "refresh-self",
        "status": "completed",
        "outcome": {
            "result": {
                "handler": "refresh-self",
                "refresh_state": "updated",
                "previous_source_sha": "a" * 40,
                "target_source_sha": "b" * 40,
                "new_broker_started": True,
                "ignored_path": "C:/secret/path",
            }
        },
    }

    payload = m.build_payload(
        accepted=accepted,
        source_sha="b" * 40,
        host=m.EXPECTED_HOST,
    )

    raw = json.dumps(payload)
    assert payload["result"]["refresh_state"] == "updated"
    assert payload["result"]["previous_source_sha"] == "a" * 40
    assert payload["result"]["target_source_sha"] == "b" * 40
    assert payload["result"]["new_broker_started"] is True
    assert "ignored_path" not in raw
    assert "secret/path" not in raw


def test_supervisor_receipt_classifies_fixed_historical_attempt(tmp_path: Path) -> None:
    import time
    control = tmp_path
    sample = {
        "schema_version": 1,
        "target_host": m.EXPECTED_HOST,
        "expected_sha": m._SUPERVISOR_SHA,
        "correlation_id": m._SUPERVISOR_CORRELATION,
        "failed_at_epoch": time.time() - 20,
        "error_type": "ValueError",
        "error": "stable bootstrap unavailable",
    }
    (control / "refresh-runtime.failed.1791500000.json").write_text(json.dumps(sample), encoding="utf-8")
    assert m._status_of_fixed_receipt(control) == {"state": "failed", "error_code": "bootstrap_unavailable"}
    assert m._status_of_fixed_receipt(control) == {"state": "failed", "error_code": "bootstrap_unavailable"}


def test_supervisor_receipt_omits_private_error_data(tmp_path: Path) -> None:
    import time
    sample = {"schema_version": 1, "target_host": m.EXPECTED_HOST, "expected_sha": m._SUPERVISOR_SHA,
              "correlation_id": m._SUPERVISOR_CORRELATION, "failed_at_epoch": time.time() - 20,
              "error_type": "RuntimeError", "error": "private path and credential string",
              "additional": {"authorization": "private example"}}
    (tmp_path / "refresh-runtime.failed.1791500000.json").write_text(json.dumps(sample))
    output = m._status_of_fixed_receipt(tmp_path)
    assert output == {"state": "failed", "error_code": "unknown"}
    assert "private" not in json.dumps(output)


@pytest.mark.parametrize("bad", [
    {"target_host": "other"}, {"expected_sha": "f" * 40},
    {"schema_version": 9}, {"failed_at_epoch": True}, {"failed_at_epoch": -1},
])
def test_supervisor_receipt_fails_closed_on_wrong_identity(tmp_path: Path, bad: dict) -> None:
    import time
    sample = {"schema_version": 1, "target_host": m.EXPECTED_HOST, "expected_sha": m._SUPERVISOR_SHA,
              "correlation_id": m._SUPERVISOR_CORRELATION, "failed_at_epoch": time.time() - 20,
              "error": "stable bootstrap unavailable"}
    sample.update(bad)
    (tmp_path / "refresh-runtime.failed.1791500000.json").write_text(json.dumps(sample))
    assert m._status_of_fixed_receipt(tmp_path) == {"state": "invalid"}


def test_supervisor_receipt_rejects_ambiguous_results(tmp_path: Path) -> None:
    import time
    base = {"schema_version": 1, "target_host": m.EXPECTED_HOST, "expected_sha": m._SUPERVISOR_SHA,
            "correlation_id": m._SUPERVISOR_CORRELATION}
    failure = dict(base, failed_at_epoch=time.time() - 20, error="stable bootstrap unavailable")
    applied = dict(base, applied_at_epoch=time.time() - 20, source_sha=m._SUPERVISOR_SHA, readback_verified=True)
    (tmp_path / "refresh-runtime.failed.1791500000.json").write_text(json.dumps(failure))
    (tmp_path / "refresh-runtime.applied.json").write_text(json.dumps(applied))
    assert m._status_of_fixed_receipt(tmp_path) == {"state": "ambiguous"}


def test_supervisor_receipt_missing_or_unavailable_is_never_ready(tmp_path: Path) -> None:
    assert m._status_of_fixed_receipt(tmp_path) == {"state": "missing"}
    assert m._status_of_fixed_receipt(tmp_path / "unavailable") == {"state": "unavailable"}


def test_supervisor_receipt_blocks_invalid_file(tmp_path: Path) -> None:
    (tmp_path / "refresh-runtime.failed.1791500000.json").write_bytes(b"x" * 9000)
    assert m._status_of_fixed_receipt(tmp_path) == {"state": "invalid"}


def test_public_readback_whitelists_only_static_receipt_status() -> None:
    accepted = {"comment_id": 12345, "action": "status", "status": "completed",
                "outcome": {"result": {"handler": "status",
                           "supervisor_receipt": {"state": "failed", "error_code": "unknown",
                                   "path": "private-file", "raw_error": "private-detail"}}}}
    payload = m.build_payload(accepted=accepted, source_sha="a" * 40, host=m.EXPECTED_HOST)
    summary = payload["result"]
    assert summary["supervisor_receipt_state"] == "failed"
    assert summary["supervisor_receipt_error_code"] == "unknown"
    assert "private" not in json.dumps(payload)
    assert payload["authoritative_success"] is False
    assert payload["trust"] == "diagnostic_only"


def test_public_readback_blocks_forged_status_and_error_code() -> None:
    accepted = {"comment_id": 12345, "action": "status", "status": "completed",
                "outcome": {"result": {"handler": "status",
                           "supervisor_receipt": {"state": "ready", "error_code": "anything"}}}}
    output = m.build_payload(accepted=accepted, source_sha="a" * 40, host=m.EXPECTED_HOST)
    assert "supervisor_receipt_state" not in output["result"]
    assert output["authoritative_success"] is False
