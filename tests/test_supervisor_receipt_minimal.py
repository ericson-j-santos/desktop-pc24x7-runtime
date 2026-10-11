"""Synthetic contract tests for read-only supervisor receipt classification."""
import importlib.util
import json
from pathlib import Path
import time

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "supervisor_refresh_receipt_probe.py"
spec = importlib.util.spec_from_file_location("supervisor_receipt_contract", SOURCE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def fixture_root(tmp_path):
    folder = tmp_path / "data" / "control"
    folder.mkdir(parents=True)
    return tmp_path


def make_receipt(root, *, kind="failed", correlation=None, **changes):
    control = root / "data" / "control"
    identity = correlation or module.CORRELATION_ID
    record = {"schema_version": 1, "correlation_id": identity,
              "target_host": module.EXPECTED_HOST, "expected_sha": module.TARGET_SHA}
    if kind == "failed":
        name = "refresh-runtime.failed.1800000000.json"
        record.update({"error_type": "ValueError", "error": "stable bootstrap unavailable",
                       "failed_at_epoch": time.time() - 20})
    elif kind == "applied":
        name = "refresh-runtime.applied.json"
        record.update({"source_sha": module.TARGET_SHA, "readback_verified": True,
                       "applied_at_epoch": time.time() - 20})
    else:
        name = "refresh-runtime.request.json"
        record.update({"version": 1, "requested_at_epoch": time.time() - 20})
    record.update(changes)
    (control / name).write_text(json.dumps(record), encoding="utf-8")
    return name


@pytest.mark.parametrize("kind", ["failed", "applied", "pending"])
def test_expected_state_is_stable_without_writes(fixture_root, kind):
    name = make_receipt(fixture_root, kind=kind)
    path = fixture_root / "data" / "control" / name
    original = path.read_bytes()
    first = module._collect(fixture_root)
    assert first == module._collect(fixture_root)
    assert path.read_bytes() == original
    assert first["receipt_state"] == kind
    assert first["recovery_allowed"] is False
    assert first["authoritative_success"] is False


def test_unrelated_attempt_does_not_count_as_evidence(fixture_root):
    make_receipt(fixture_root, correlation="unrelated-execution")
    with pytest.raises(module.ReceiptError, match="matching_receipt_missing"):
        module._collect(fixture_root)


def test_sensitive_exception_message_is_omitted(fixture_root):
    name = make_receipt(fixture_root)
    path = fixture_root / "data" / "control" / name
    record = json.loads(path.read_text())
    record["error"] = "PRIVATE_CREDENTIAL_SECRET"
    path.write_text(json.dumps(record))
    result = module._collect(fixture_root)
    assert result["error_code"] == "unclassified_error"
    assert "PRIVATE_CREDENTIAL_SECRET" not in json.dumps(result)


def test_wrong_target_fails_closed(fixture_root):
    make_receipt(fixture_root, expected_sha="f" * 40)
    with pytest.raises(module.ReceiptError, match="receipt_identity_mismatch"):
        module._collect(fixture_root)
