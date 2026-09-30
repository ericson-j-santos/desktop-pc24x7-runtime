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
