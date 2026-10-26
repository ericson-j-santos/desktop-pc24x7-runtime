from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "lenovo_control_plane_pickup", SCRIPTS / "lenovo_control_plane_pickup.py"
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def valid_env(monkeypatch, sha: str) -> None:
    values = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": m.EXPECTED_REPOSITORY,
        "GITHUB_SHA": sha,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_NAME": m.EXPECTED_RUNNER,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_positive_pickup_binds_host_runner_task_state_and_sha(
    monkeypatch, tmp_path: Path
) -> None:
    sha = "a" * 40
    valid_env(monkeypatch, sha)
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.EXPECTED_HOST)
    monkeypatch.setattr(
        m,
        "load_task_bound_installation",
        lambda root, expected: {
            "metadata": {"source_sha": expected},
            "runner_home": tmp_path / "runner",
        },
    )
    monkeypatch.setattr(
        m.watchdog,
        "task_status",
        lambda: {"exists": True, "trigger_at_startup": True, "logon_type": "S4U"},
    )
    monkeypatch.setattr(
        m,
        "task_runtime_readback",
        lambda: {
            "state": 4,
            "last_task_result": 267009,
            "enabled": True,
            "launcher": str(tmp_path / "run.py"),
            "working_directory": str(tmp_path),
        },
    )
    monkeypatch.setattr(
        m,
        "read_state",
        lambda root, expected: {
            "source_sha": expected,
            "ok": True,
            "runner_recovery_ok": True,
            "rdc_required": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "github_runner": {"status": "process_running"},
        },
    )
    monkeypatch.setattr(
        m.watchdog,
        "runner_process_snapshot",
        lambda home: {"matching_pids": [4321], "unresolved_pids": []},
    )

    result = m.collect(sha)

    assert result["result"] == "LENOVO_CONTROL_PLANE_PICKUP_PROVEN"
    assert result["source_sha"] == sha
    assert result["runner_name"] == m.EXPECTED_RUNNER
    assert result["runner_pids"] == [4321]
    assert result["rdc_required"] is False


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("GITHUB_ACTIONS", "false", "github_actions_required"),
        ("GITHUB_EVENT_NAME", "push", "workflow_dispatch_required"),
        ("GITHUB_REPOSITORY", "other/repo", "repository_mismatch"),
        ("RUNNER_NAME", "DESKTOP-PDQK954-runtime", "runner_name_mismatch"),
        ("GITHUB_SHA", "b" * 40, "github_sha_mismatch"),
    ],
)
def test_wrong_dispatch_identity_fails_closed(
    monkeypatch, key: str, value: str, reason: str
) -> None:
    sha = "a" * 40
    valid_env(monkeypatch, sha)
    monkeypatch.setenv(key, value)
    with pytest.raises(m.PickupBlocked, match=reason):
        m.collect(sha)


def test_stale_state_is_rejected(tmp_path: Path) -> None:
    state = {
        "source_sha": "a" * 40,
        "ok": True,
        "runner_recovery_ok": True,
        "rdc_required": False,
        "generated_at": "2020-01-01T00:00:00+00:00",
    }
    (tmp_path / "state.json").write_text(__import__("json").dumps(state), encoding="utf-8")
    with pytest.raises(m.PickupBlocked, match="watchdog_state_stale"):
        m.read_state(tmp_path, "a" * 40)


def test_false_runner_state_is_rejected(tmp_path: Path) -> None:
    state = {
        "source_sha": "a" * 40,
        "ok": True,
        "runner_recovery_ok": True,
        "rdc_required": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "github_runner": {"status": "failed"},
    }
    (tmp_path / "state.json").write_text(__import__("json").dumps(state), encoding="utf-8")
    with pytest.raises(m.PickupBlocked, match="watchdog_runner_state_invalid"):
        m.read_state(tmp_path, "a" * 40)


def test_task_bound_metadata_rejects_runtime_split(tmp_path: Path) -> None:
    sha = "a" * 40
    other = tmp_path / "other"
    release = other / "releases" / sha
    (release / "scripts").mkdir(parents=True)
    (release / "scripts" / "desktop_control_plane_watchdog.py").write_text(
        "# watchdog\n", encoding="utf-8"
    )
    (tmp_path / "metadata.json").write_text(
        __import__("json").dumps(
            {
                "source_sha": sha,
                "runtime_root": str(other),
                "release_root": str(release),
                "runner_home": str(tmp_path / "runner"),
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(m.PickupBlocked, match="metadata_runtime_contract_mismatch"):
        m.load_task_bound_installation(tmp_path.resolve(), sha)
