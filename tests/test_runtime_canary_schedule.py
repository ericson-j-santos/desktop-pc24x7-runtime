"""Guard against unbounded repeated physical pickup after a 300s outage.

Keep a bounded hourly half-open probe; owner manual recovery remains available.
This verifies scheduling/control contracts, not physical runner availability.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "runtime-canary.yml"
EXPECTED_LABELS = [
    "self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime",
    "runtime-dev", "desktop-pdqk954",
]


def assert_bounded_canary_contract(source: str) -> None:
    data = yaml.load(source, Loader=yaml.BaseLoader)
    assert isinstance(data, dict)
    events = data["on"]
    assert set(events) == {"schedule", "workflow_dispatch", "pull_request"}
    assert events["schedule"] == [{"cron": "17 * * * *"}]
    jobs = data["jobs"]
    assert set(jobs) == {"canary", "queue_watchdog"}
    assert jobs["canary"]["runs-on"] == EXPECTED_LABELS
    assert jobs["canary"]["concurrency"]["cancel-in-progress"] == "false"
    assert jobs["queue_watchdog"]["env"]["STALL_AFTER_SECONDS"] == "300"
    assert jobs["queue_watchdog"]["env"]["EXPECTED_RUNNER"] == "DESKTOP-PDQK954-runtime"
    assert jobs["queue_watchdog"]["permissions"]["actions"] == "write"
    assert "progress_watchdog.py" in source
    assert "cancelWorkflowRun" in source
    assert source.count("github.event.pull_request.draft") == 2


def test_hourly_half_open_preserves_owner_and_fail_closed_watchdog() -> None:
    assert_bounded_canary_contract(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("old", "bad"),
    [
        ('17 * * * *', '*/5 * * * *'),
        ('17 * * * *', '* * * * *'),
        ('  workflow_dispatch:', '  unexpected_dispatch:'),
        ('STALL_AFTER_SECONDS: "300"', 'STALL_AFTER_SECONDS: "3600"'),
        ('desktop-pdqk954]', 'desktop-rp23ogs]'),
        ('cancelWorkflowRun', 'silentContinue'),
        ('github.event.pull_request.draft', 'github.event.pull_request.other'),
    ],
)
def test_mutated_cadence_or_security_gate_fails_closed(old: str, bad: str) -> None:
    good = WORKFLOW.read_text(encoding="utf-8")
    assert old in good
    mutated = good.replace(old, bad)
    assert mutated != good
    with pytest.raises((AssertionError, KeyError, TypeError)):
        assert_bounded_canary_contract(mutated)
