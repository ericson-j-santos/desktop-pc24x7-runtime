from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "quarantine_lenovo_legacy_startup.py"
SPEC = importlib.util.spec_from_file_location("quarantine_lenovo_legacy_startup", SCRIPT)
assert SPEC and SPEC.loader
q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(q)


def fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    startup = tmp_path / "Start-RP23OGS-Runner.cmd"
    startup.write_bytes(b"fixed startup entry")
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "metadata.json").write_text(json.dumps({"host": q.HOST, "source_sha": q.SOURCE_SHA}))
    runner = tmp_path / "GitHubRunner" / "bin" / "Runner.Listener.exe"
    runner.parent.mkdir(parents=True)
    runner.write_bytes(b"")
    monkeypatch.setattr(q, "STARTUP", startup)
    monkeypatch.setattr(q, "QUARANTINED", startup.with_name(startup.name + ".disabled"))
    monkeypatch.setattr(q, "ENTRY_SHA256", hashlib.sha256(startup.read_bytes()).hexdigest())
    monkeypatch.setattr(q, "RUNTIME", runtime)
    monkeypatch.setattr(q, "RUNNER", runner)
    monkeypatch.setattr(q.os, "name", "nt")
    monkeypatch.setattr(q.socket, "gethostname", lambda: q.HOST)
    return startup, runner


def test_exact_startup_duplicate_is_quarantined_and_stopped(monkeypatch, tmp_path):
    startup, runner = fixture(monkeypatch, tmp_path)
    processes = {
        2024: {"pid": 2024, "parent_pid": 12552, "name": "Runner.Listener.exe", "path": str(runner), "command": "run"},
        12552: {"pid": 12552, "parent_pid": 5412, "name": "cmd.exe", "path": "cmd.exe", "command": str(startup)},
    }
    monkeypatch.setattr(q, "process", lambda pid: processes.get(pid))
    def stop(args, **kwargs):
        assert args[-3:] == ["/PID", "2024", "/T"]
        processes.pop(2024)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(q.subprocess, "run", stop)
    assert q.preflight(2024)["duplicate_pid"] == 2024
    result = q.apply(2024)
    assert result["result"] == "LEGACY_STARTUP_QUARANTINED"
    assert not startup.exists() and q.QUARANTINED.is_file()
    with pytest.raises(q.Blocked, match="startup_entry_changed"):
        q.apply(2024)


def test_wrong_parent_or_digest_never_moves_or_kills(monkeypatch, tmp_path):
    startup, runner = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(q, "process", lambda pid: {"pid": pid, "parent_pid": 5, "name": "Runner.Listener.exe", "path": str(runner), "command": "run"})
    monkeypatch.setattr(q.subprocess, "run", lambda *args, **kwargs: pytest.fail("must not kill"))
    with pytest.raises(q.Blocked, match="duplicate_parent_missing"):
        q.apply(2024)
    assert startup.is_file()
    startup.write_bytes(b"changed")
    with pytest.raises(q.Blocked, match="digest_changed"):
        q.apply(2024)
    assert startup.is_file()


def test_duplicate_already_exited_quarantines_without_kill(monkeypatch, tmp_path):
    startup, _ = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(q, "legacy_startup_commands", lambda: [])
    monkeypatch.setattr(q.subprocess, "run", lambda *args, **kwargs: pytest.fail("must not kill"))
    result = q.apply(0)
    assert result["duplicate_pid"] is None
    assert result["duplicate_stopped"] is True
    assert result["result"] == "LEGACY_STARTUP_QUARANTINED"
    assert not startup.exists() and q.QUARANTINED.is_file()


def test_pending_startup_command_blocks_quarantine(monkeypatch, tmp_path):
    startup, _ = fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(q, "legacy_startup_commands", lambda: [12552])
    with pytest.raises(q.Blocked, match="still_running"):
        q.apply(0)
    assert startup.is_file()
