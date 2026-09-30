from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "noteri_desktop_orchestrator_rdc_recovery.py"
SPEC = importlib.util.spec_from_file_location("rdc_recovery", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_intake_is_fixed_and_risk_two() -> None:
    intake = m.build_intake("corr-rdc-recovery-123")
    assert intake["task_type"] == "host.rdc.recover.v1"
    assert intake["risk"] == 2
    assert intake["max_attempts"] == 1
    assert intake["payload"] == {
        "target_host": "DESKTOP-PDQK954",
        "force_restart": False,
    }
    assert "command" not in intake["payload"]
    assert "path" not in intake["payload"]
    assert "url" not in intake["payload"]


def test_validate_result_rejects_wrong_target() -> None:
    item = {
        "result": {
            "handler": m.TASK_TYPE,
            "host": "OTHER-HOST",
            "task": m.EXPECTED_TASK,
            "launcher": m.EXPECTED_LAUNCHER,
            "after": {"enabled": True},
            "running_instance": "abc",
        }
    }
    with pytest.raises(m.RecoveryError, match="host_mismatch"):
        m.validate_result(item)


def test_execute_replays_same_item_without_second_effect() -> None:
    worker = {
        "capabilities": {
            "safe_task_types": [m.TASK_TYPE],
            "worker_instance_id": "a" * 32,
        }
    }
    terminal = {
        "status": m.COMPLETED,
        "result": {
            "handler": m.TASK_TYPE,
            "host": m.TARGET_HOST,
            "task": m.EXPECTED_TASK,
            "launcher": m.EXPECTED_LAUNCHER,
            "after": {"enabled": True},
            "running_instance": "instance-1",
        },
    }
    first = {"item": {"id": "item-1"}, "created": True, "replayed": False}
    replay = {"item": {"id": "item-1"}, "created": False, "replayed": True}
    with (
        patch.object(m, "validate_source_host", return_value="Noteri"),
        patch.object(m, "read_worker", side_effect=[worker, worker]),
        patch.object(m, "submit", side_effect=[(201, first), (200, replay)]),
        patch.object(m, "wait_terminal", return_value=terminal),
    ):
        result = m.execute(
            m.CONFIRM,
            "corr-rdc-recovery-123",
            30,
        )
    assert result["ok"] is True
    assert result["replayed"] is True
    assert result["rdc_task_started"] is True
    assert result["production_touched"] is False
