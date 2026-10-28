from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "dispatch_lenovo_postboot_pickup.py"
SPEC = importlib.util.spec_from_file_location("dispatch_lenovo_postboot_pickup", SCRIPT)
assert SPEC and SPEC.loader
d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d)


def setup(monkeypatch, tmp_path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "metadata.json").write_text(json.dumps({"source_sha": d.quarantine.SOURCE_SHA}))
    (runtime / "state.json").write_text(json.dumps({
        "source_sha": d.quarantine.SOURCE_SHA, "ok": True,
        "runner_recovery_ok": True, "generated_at": datetime.now(timezone.utc).isoformat(),
    }))
    startup = tmp_path / "startup.cmd"
    disabled = tmp_path / "startup.cmd.disabled"
    disabled.write_bytes(b"original")
    monkeypatch.setattr(d.quarantine, "RUNTIME", runtime)
    monkeypatch.setattr(d.quarantine, "STARTUP", startup)
    monkeypatch.setattr(d.quarantine, "QUARANTINED", disabled)
    monkeypatch.setattr(d.quarantine, "ENTRY_SHA256", hashlib.sha256(b"original").hexdigest())
    monkeypatch.setattr(d.os, "name", "nt")
    monkeypatch.setattr(d.socket, "gethostname", lambda: d.quarantine.HOST)
    monkeypatch.setattr(d.pickup, "task_runtime_readback", lambda: {"state": 4, "enabled": True})


def test_exact_preflight_and_one_dispatch(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    calls = []
    def fake_gh(*args, **kwargs):
        calls.append(args)
        path = args[1] if len(args) > 1 else ""
        if path.endswith("/commits/" + d.quarantine.SOURCE_SHA):
            return {"sha": d.quarantine.SOURCE_SHA}
        if path.endswith("/actions/runners?per_page=100"):
            return {"total_count": 1, "runners": [{"id": 24, "name": "DESKTOP-RP23OGS-runtime", "status": "online", "busy": False}]}
        if args[:3] == ("api", "-X", "POST"):
            return {"ref": "refs/heads/" + d.REF}
        if path.endswith("/git/ref/heads/" + d.REF):
            return {"object": {"sha": d.quarantine.SOURCE_SHA}} if any(x[:3] == ("api", "-X", "POST") for x in calls) else {}
        raise AssertionError(args)
    monkeypatch.setattr(d, "gh", fake_gh)
    monkeypatch.setattr(d.shutil, "which", lambda _: "gh.exe")
    dispatched = []
    monkeypatch.setattr(d.subprocess, "run", lambda args, **kw: (dispatched.append(args), SimpleNamespace(returncode=0))[1])
    result = d.execute()
    assert result["result"] == "DISPATCH_REQUEST_ACCEPTED"
    assert sum(x[:3] == ("api", "-X", "POST") for x in calls) == 1
    assert len(dispatched) == 1
    assert dispatched[0][1:3] == ["workflow", "run"]


def test_existing_branch_blocks_before_dispatch(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    def fake_gh(*args, **kwargs):
        path = args[1]
        if path.endswith("/commits/" + d.quarantine.SOURCE_SHA):
            return {"sha": d.quarantine.SOURCE_SHA}
        if path.endswith("/git/ref/heads/" + d.REF):
            return {"object": {"sha": d.quarantine.SOURCE_SHA}}
        pytest.fail("write or registry read after existing branch")
    monkeypatch.setattr(d, "gh", fake_gh)
    with pytest.raises(d.Blocked, match="no_replay"):
        d.execute()
