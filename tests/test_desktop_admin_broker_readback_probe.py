from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "desktop_admin_broker_readback_probe.py"
SPEC = importlib.util.spec_from_file_location("desktop_admin_broker_readback_probe", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def message_event(
    *,
    generated_at: str,
    host: str = m.EXPECTED_HOST,
    comment_id: int = 5856419547,
) -> dict:
    payload = {
        "schema_version": "1",
        "generated_at": generated_at,
        "trust": "diagnostic_only",
        "authoritative_success": False,
        "host": host,
        "source_sha": "a" * 40,
        "comment_id": comment_id,
        "action": "status",
        "status": "completed",
        "error_code": "",
        "production_touched": False,
        "secrets_read": False,
        "result": {
            "handler": "status",
            "local_recovery_ok": True,
            "ignored_secret": "must-not-leak",
        },
    }
    return {
        "id": "message-123",
        "time": 1_750_000_000,
        "event": "message",
        "topic": m.TOPIC,
        "message": json.dumps(payload),
    }


def validate_bound(
    event: dict,
    *,
    reference: datetime,
    requested_at: str = "2026-09-27T13:44:00+00:00",
    expected_comment_id: int = 5856419547,
) -> dict:
    return m.validate_message(
        event,
        max_age_seconds=900,
        expected_comment_id=expected_comment_id,
        requested_at=requested_at,
        reference_time=reference,
    )


def test_valid_readback_is_sanitized() -> None:
    reference = datetime(2026, 9, 27, 13, 45, tzinfo=timezone.utc)
    event = message_event(generated_at="2026-09-27T13:44:30+00:00")

    result = validate_bound(event, reference=reference)

    raw = json.dumps(result)
    assert result["ok"] is True
    assert result["source_sha"] == "a" * 40
    assert result["comment_id"] == 5856419547
    assert result["authoritative_success"] is False
    assert result["error_code"] == ""
    assert result["result_summary"]["handler"] == "status"
    assert "ignored_secret" not in raw
    assert "must-not-leak" not in raw


def test_stale_or_wrong_host_fails_closed() -> None:
    reference = datetime(2026, 9, 27, 14, 30, tzinfo=timezone.utc)
    stale = message_event(generated_at="2026-09-27T13:00:00+00:00")
    with pytest.raises(m.ProbeError, match="readback_not_fresh"):
        validate_bound(stale, reference=reference)

    wrong_host = message_event(
        generated_at="2026-09-27T14:29:30+00:00",
        host="OTHER-HOST",
    )
    with pytest.raises(m.ProbeError, match="readback_host_invalid"):
        validate_bound(
            wrong_host,
            reference=reference,
            requested_at="2026-09-27T14:29:00+00:00",
        )


def test_request_binding_rejects_other_comment_and_pre_request_message() -> None:
    reference = datetime(2026, 9, 27, 13, 45, tzinfo=timezone.utc)
    other = message_event(
        generated_at="2026-09-27T13:44:30+00:00",
        comment_id=5856419548,
    )
    with pytest.raises(m.ProbeError, match="readback_comment_mismatch"):
        validate_bound(other, reference=reference)

    before = message_event(generated_at="2026-09-27T13:43:30+00:00")
    with pytest.raises(m.ProbeError, match="readback_before_request"):
        validate_bound(before, reference=reference)


def test_workflow_resolves_exact_unedited_owner_request() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "desktop-admin-broker-readback-probe.yml"
    ).read_text(encoding="utf-8")
    assert "issues: read" in workflow
    assert "github.paginate" in workflow
    assert "issue_number: 2" in workflow
    assert "comment.body === '/desktop-runtime admin status'" in workflow
    assert "comment.updated_at === comment.created_at" in workflow
    assert "--expected-comment-id" in workflow
    assert "--requested-at" in workflow
    live = workflow.split("\n  live-probe:\n", 1)[1]
    assert "if: github.event_name == 'workflow_dispatch'" in live
    contract = workflow.split("\n  contract:\n", 1)[1].split("\n  live-probe:\n", 1)[0]
    assert "workflow_dispatch" not in contract


def test_live_probe_cannot_become_push_gate_by_mutation() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "desktop-admin-broker-readback-probe.yml"
    ).read_text(encoding="utf-8")
    live = workflow.split("\n  live-probe:\n", 1)[1]
    assert "if: github.event_name == 'workflow_dispatch'" in live
    weakened = live.replace("if: github.event_name == 'workflow_dispatch'", "", 1)
    assert "if: github.event_name == 'workflow_dispatch'" not in weakened


def test_fetch_uses_fixed_poll_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}
    body = (
        json.dumps({"event": "open", "topic": m.TOPIC}) + "\n"
        + json.dumps(
            message_event(generated_at="2026-09-27T13:44:30+00:00")
        )
        + "\n"
    ).encode("utf-8")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, limit):
            captured["limit"] = limit
            return body

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(m.urllib.request, "urlopen", fake_urlopen)
    events = m.fetch_latest(timeout_seconds=4)

    assert captured["url"] == m.ENDPOINT
    assert captured["limit"] == m.MAX_RESPONSE_BYTES + 1
    assert len(events) == 2
    assert events[-1]["event"] == "message"


def test_probe_rejects_absent_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        m,
        "fetch_latest",
        lambda timeout_seconds=10.0: [{"event": "open", "topic": m.TOPIC}],
    )
    with pytest.raises(m.ProbeError, match="ntfy_message_missing"):
        m.probe(
            max_age_seconds=900,
            expected_comment_id=5856419547,
            requested_at="2026-09-27T13:44:00+00:00",
        )


def test_failed_readback_exposes_only_sanitized_error_code() -> None:
    reference = datetime(2026, 9, 27, 13, 45, tzinfo=timezone.utc)
    event = message_event(generated_at="2026-09-27T13:44:30+00:00")
    payload = json.loads(event["message"])
    payload["status"] = "failed"
    payload["error_code"] = "BrokerError"
    payload["error_detail"] = "secret-detail-must-not-leak"
    event["message"] = json.dumps(payload)

    result = validate_bound(event, reference=reference)

    raw = json.dumps(result)
    assert result["status"] == "failed"
    assert result["error_code"] == "BrokerError"
    assert "secret-detail-must-not-leak" not in raw


def test_probe_retains_self_refresh_summary() -> None:
    reference = datetime(2026, 9, 27, 13, 45, tzinfo=timezone.utc)
    event = message_event(generated_at="2026-09-27T13:44:30+00:00")
    payload = json.loads(event["message"])
    payload["action"] = "refresh-self"
    payload["result"] = {
        "handler": "refresh-self",
        "refresh_state": "updated",
        "previous_source_sha": "a" * 40,
        "target_source_sha": "b" * 40,
        "new_broker_started": True,
        "ignored_path": "C:/secret/path",
    }
    event["message"] = json.dumps(payload)

    result = validate_bound(event, reference=reference)

    raw = json.dumps(result)
    assert result["result_summary"]["refresh_state"] == "updated"
    assert result["result_summary"]["target_source_sha"] == "b" * 40
    assert result["result_summary"]["new_broker_started"] is True
    assert "ignored_path" not in raw
