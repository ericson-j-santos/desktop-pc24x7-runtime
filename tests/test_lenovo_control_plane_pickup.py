from __future__ import annotations

import importlib.util
import json
import subprocess
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


def test_task_runtime_uses_fixed_inbox_readback_without_pywin32(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launcher = tmp_path / "run.py"
    launcher.touch()
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps({
                "state": 4,
                "last_task_result": 267009,
                "enabled": True,
                "command": sys.executable,
                "arguments": f'"{launcher}"',
                "working_directory": str(tmp_path),
            }),
            "",
        )

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    observed = m.task_runtime_readback()

    assert observed == {
        "state": 4,
        "last_task_result": 267009,
        "enabled": True,
        "launcher": str(launcher),
        "working_directory": str(tmp_path),
    }
    assert len(calls) == 1
    assert calls[0][0][1:3] == ["-NoProfile", "-NonInteractive"]
    assert "Get-ScheduledTaskInfo" in calls[0][0][4]
    assert calls[0][1]["timeout"] == 20
    assert calls[0][1]["check"] is False


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    [(1, "", "denied"), (0, "not json", ""), (0, "{}", "warning")],
)
def test_task_runtime_readback_fails_closed_on_provider_error(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str
) -> None:
    monkeypatch.setattr(
        m.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, returncode, stdout, stderr
        ),
    )
    with pytest.raises(m.PickupBlocked, match="task_runtime_readback_failed"):
        m.task_runtime_readback()


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


def test_readback_dependency_failure_writes_only_bounded_failure_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sha = "a" * 40
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_TOKEN", "must-never-appear")
    monkeypatch.setattr(
        m,
        "collect",
        lambda expected: (_ for _ in ()).throw(m.PickupBlocked("task_runtime_readback_failed")),
    )
    monkeypatch.setattr(
        sys, "argv", ["pickup.py", "--expected-source-sha", sha, "--evidence-file", m.EVIDENCE_REL]
    )

    assert m.main() == 3
    evidence = tmp_path / "artifacts" / "lenovo-control-plane-pickup" / "evidence.json"
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": "1",
        "ok": False,
        "result": "BLOCKED",
        "reason": "task_runtime_readback_failed",
        "source_sha": sha,
        "github_run_id": "123",
        "github_run_attempt": "1",
    }
    assert "must-never-appear" not in evidence.read_text(encoding="utf-8")
    assert json.loads(capsys.readouterr().out) == payload


def test_failure_reason_with_untrusted_text_is_redacted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        m, "collect", lambda expected: (_ for _ in ()).throw(m.PickupBlocked("secret=do-not-log"))
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["pickup.py", "--expected-source-sha", "a" * 40, "--evidence-file", m.EVIDENCE_REL],
    )
    assert m.main() == 3
    payload = json.loads(
        (tmp_path / "artifacts" / "lenovo-control-plane-pickup" / "evidence.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["reason"] == "pickup_dependency_or_state_error"


def test_probe_rejects_arbitrary_evidence_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(m, "collect", lambda expected: pytest.fail("probe must not run"))
    monkeypatch.setattr(
        sys,
        "argv",
        ["pickup.py", "--expected-source-sha", "a" * 40, "--evidence-file", "elsewhere.json"],
    )
    assert m.main() == 3
    assert not (tmp_path / "elsewhere.json").exists()
