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


def message_event(*, generated_at: str, host: str = m.EXPECTED_HOST) -> dict:
    payload = {
        "schema_version": "1",
        "generated_at": generated_at,
        "trust": "diagnostic_only",
        "authoritative_success": False,
        "host": host,
        "source_sha": "a" * 40,
        "comment_id": 5856419547,
        "action": "status",
        "status": "completed",
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


def test_valid_readback_is_sanitized() -> None:
    reference = datetime(2026, 9, 27, 13, 45, tzinfo=timezone.utc)
    event = message_event(generated_at="2026-09-27T13:44:30+00:00")

    result = m.validate_message(
        event,
        max_age_seconds=900,
        reference_time=reference,
    )

    raw = json.dumps(result)
    assert result["ok"] is True
    assert result["source_sha"] == "a" * 40
    assert result["comment_id"] == 5856419547
    assert result["authoritative_success"] is False
    assert result["result_summary"]["handler"] == "status"
    assert "ignored_secret" not in raw
    assert "must-not-leak" not in raw


def test_stale_or_wrong_host_fails_closed() -> None:
    reference = datetime(2026, 9, 27, 14, 30, tzinfo=timezone.utc)
    stale = message_event(generated_at="2026-09-27T13:00:00+00:00")
    with pytest.raises(m.ProbeError, match="readback_not_fresh"):
        m.validate_message(stale, max_age_seconds=900, reference_time=reference)

    wrong_host = message_event(
        generated_at="2026-09-27T14:29:30+00:00",
        host="OTHER-HOST",
    )
    with pytest.raises(m.ProbeError, match="readback_host_invalid"):
        m.validate_message(wrong_host, max_age_seconds=900, reference_time=reference)


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
        m.probe(max_age_seconds=900)
