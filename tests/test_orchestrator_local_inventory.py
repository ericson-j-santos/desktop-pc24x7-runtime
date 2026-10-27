from __future__ import annotations

import hashlib
import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import bootstrap_dedicated_runtime_runner as b
import desktop_control_plane_watchdog as w
import orchestrator_dev_runner_preflight as p
import orchestrator_runner_preflight_workflow as h

HEAD = "a" * 40
CORRELATION = "dedicated-runner-77-1"
BLOCK = "github_local_auth_required"
PRIVATE = "private-value-must-not-reach-public-output"


@pytest.fixture
def installation(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    root = local / "DesktopPC24x7" / "ControlPlaneWatchdog"
    primary = local / "DesktopPC24x7" / "GitHubRunner"
    release = root / "releases" / HEAD
    python = local / "fixed-python.exe"
    (release / "scripts").mkdir(parents=True)
    (primary / "bin").mkdir(parents=True)
    python.write_bytes(b"not executed")
    for name in ("desktop_control_plane_watchdog.py", w.UAC_LAUNCHER_SCRIPT, w.HOST_POLICY_SCRIPT):
        (release / "scripts" / name).write_bytes(b"fixed installed source\n")
    (root / "run.py").write_bytes(b"fixed launcher\n")
    for parts in w.RUNNER_REQUIRED:
        primary.joinpath(*parts).write_text(PRIVATE, encoding="utf-8")
    metadata = {
        "runtime_root": str(root), "release_root": str(release),
        "runner_home": str(primary), "python_executable": str(python),
        "source_sha": HEAD, "host": "DESKTOP-PDQK954", "unknown_private": PRIVATE,
    }
    (root / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (root / "state.json").write_text(json.dumps({
        "ok": True, "source_sha": HEAD, "generated_at": datetime.now(timezone.utc).isoformat(),
        "unknown_private": PRIVATE,
    }), encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(w, "require_windows_desktop", lambda: "DESKTOP-PDQK954")
    monkeypatch.setattr(w.socket, "gethostname", lambda: "DESKTOP-PDQK954")
    monkeypatch.setattr(w, "task_status", lambda: {"exists": True, "trigger_at_startup": True})
    monkeypatch.setattr(w, "task_runtime_snapshot", lambda: {"state": 4, "enabled": True})
    monkeypatch.setattr(w, "_inventory_task_identity", lambda installed: {
        "process_user_matches_task_principal": True,
        "task_s4u": True, "task_limited": True,
        "task_action_matches_installation": True if installed else None,
    })
    def process(home):
        assert home == primary
        return {"matching_pids": [1234], "unresolved_pids": [], "observed": [{"path": PRIVATE}]}
    monkeypatch.setattr(w, "runner_process_snapshot", process)
    return SimpleNamespace(local=local, root=root, primary=primary, release=release, python=python, metadata=metadata)


def test_local_inventory_reads_fixed_installation_without_mutation_or_private_output(installation, monkeypatch):
    paths = [path for path in installation.local.rglob("*") if path.is_file()]
    before = {str(path): path.read_bytes() for path in paths}
    original_open = Path.open
    def guarded_open(path, *args, **kwargs):
        assert path.name not in {".runner", ".credentials", ".credentials_rsaparams"}
        return original_open(path, *args, **kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "open", guarded_open)
        result = w.readonly_local_inventory()
    assert result["metadata_status"] == "observed"
    assert result["installed_source_sha"] == HEAD
    assert result["metadata_sha256"] == hashlib.sha256(before[str(installation.root / "metadata.json")]).hexdigest()
    assert result["launcher_sha256"] == hashlib.sha256(b"fixed launcher\n").hexdigest()
    assert result["runtime_listener_pid"] == 1234
    assert result["orchestrator_home_status"] == "missing"
    assert result["process_user_matches_task_principal"] is True
    assert result["state_fresh_300s"] is True
    public = json.dumps(result)
    assert PRIVATE not in public
    assert str(installation.local) not in public
    assert {str(path): path.read_bytes() for path in paths} == before
    assert not (installation.local / "EngineeringOrchestratorDEV").exists()


def test_bad_metadata_does_not_suppress_task_state_or_runtime_process(installation):
    (installation.root / "metadata.json").write_text("{", encoding="utf-8")
    result = w.readonly_local_inventory()
    assert result["metadata_status"] == "invalid"
    assert result["task_runtime_status"] == "observed"
    assert result["runtime_listener_pid"] == 1234
    assert result["state_status"] == "observed"
    assert result["task_action_matches_installation"] is None


@pytest.mark.parametrize("field", ["runtime_root", "release_root", "runner_home", "host"])
def test_local_inventory_rejects_metadata_outside_closed_scope(installation, field):
    metadata = dict(installation.metadata)
    metadata[field] = "OTHER-HOST" if field == "host" else str(installation.local / "other")
    (installation.root / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    result = w.readonly_local_inventory()
    assert result["metadata_status"] == "invalid"
    assert result["runtime_listener_pid"] == 1234
    assert result["task_action_matches_installation"] is None


@pytest.mark.parametrize("which", ["local", "ancestor"])
def test_reparse_ancestor_blocks_file_reads_but_keeps_fixed_task_readback(installation, monkeypatch, which):
    rejected = installation.local if which == "local" else installation.local.parent
    original = Path.lstat
    def reparse(path, *args, **kwargs):
        if path == rejected:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", reparse)
    result = w.readonly_local_inventory()
    assert result["paths_status"] == "blocked"
    assert result["metadata_sha256"] is None
    assert result["runtime_listener_pid"] is None
    assert result["task_runtime_status"] == "observed"


def test_inventory_files_are_bounded_and_duplicate_json_is_rejected(tmp_path):
    path = tmp_path / "fixed.json"
    path.write_bytes(b"x" * 17)
    with pytest.raises(w.WatchdogError, match="inventory_file_too_large"):
        w._inventory_bytes(path, 16)
    path.write_bytes(b'{"source_sha":"one","source_sha":"two"}')
    with pytest.raises(ValueError, match="duplicate_key"):
        w._inventory_json(path)


@pytest.mark.parametrize("same_user", [True, False])
def test_task_identity_compares_sids_in_memory_and_returns_only_booleans(monkeypatch, tmp_path, same_user):
    installed = {
        "python_executable": tmp_path / "python.exe",
        "launcher": tmp_path / "run.py", "runtime_root": tmp_path,
    }
    principal_sid = "S-1-5-21-111"
    process_sid = principal_sid if same_user else "S-1-5-21-222"
    token = SimpleNamespace(closed=False)
    token.Close = lambda: setattr(token, "closed", True)
    definition = SimpleNamespace(
        Principal=SimpleNamespace(UserId="PRIVATE-DOMAIN\\private-user", LogonType=2, RunLevel=0),
        Actions=SimpleNamespace(Count=1, Item=lambda index: SimpleNamespace(
            Type=0, Path=str(installed["python_executable"]),
            Arguments=f'"{installed["launcher"]}"', WorkingDirectory=str(tmp_path),
        )),
    )
    def get_folder(name):
        assert name == w.TASK_FOLDER
        return SimpleNamespace(GetTask=lambda leaf: SimpleNamespace(Definition=definition) if leaf == w.TASK_LEAF else None)
    service = SimpleNamespace(Connect=lambda: None, GetFolder=get_folder)
    client = ModuleType("win32com.client")
    client.Dispatch = lambda name: service if name == "Schedule.Service" else None
    com = ModuleType("win32com")
    com.client = client
    api = ModuleType("win32api")
    api.GetCurrentProcess = lambda: "current-process"
    security = ModuleType("win32security")
    def open_token(process, access):
        assert process == "current-process" and access == 0x0008
        return token
    security.OpenProcessToken = open_token
    security.GetTokenInformation = lambda handle, kind: (process_sid, 0)
    security.ConvertSidToStringSid = lambda value: value
    security.TokenUser = 1
    for name, module in (("win32com", com), ("win32com.client", client), ("win32api", api), ("win32security", security)):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(w, "current_user_sid", lambda user: principal_sid)
    result = w._inventory_task_identity(installed)
    assert token.closed is True
    assert result == {
        "process_user_matches_task_principal": same_user, "task_s4u": True,
        "task_limited": True, "task_action_matches_installation": True,
    }
    assert principal_sid not in json.dumps(result)
    assert "private-user" not in json.dumps(result)


@pytest.fixture
def diagnostic(monkeypatch):
    calls = []
    monkeypatch.setattr(p, "require_source", lambda sha: calls.append(("source", sha)))
    monkeypatch.setattr(b, "validate_host", lambda: "DESKTOP-PDQK954")
    monkeypatch.setattr(b, "find_gh", lambda: None)
    def forbidden(*args, **kwargs):
        pytest.fail("local diagnostic must not authenticate or invoke a GitHub API")
    monkeypatch.setattr(b, "api_json", forbidden)
    monkeypatch.setattr(b, "local_gh_api_json", forbidden)
    def loopback(path):
        calls.append(("http", path))
        if path == "/readyz":
            return {"ready": True, "private": PRIVATE}
        return {"workers": [{
            "device_name": "DESKTOP-PDQK954", "fresh": True,
            "controller_online": True, "auth_valid": False, "profile": "NORMAL",
            "private": PRIVATE,
        }]}
    monkeypatch.setattr(p, "read_loopback", loopback)
    monkeypatch.setattr(w, "readonly_local_inventory", lambda: {"metadata_status": "missing"})
    return calls


def test_diagnostic_auth_block_keeps_independent_loopback_and_local_facts(diagnostic):
    result = p.local_failure_inventory(expected_sha=HEAD, correlation_id=CORRELATION, preflight_state=BLOCK)
    assert result["github_cli_status"] == "not_located"
    assert result["github_owner_validation"] == "not_validated"
    assert result["loopback_ready"] is True
    assert result["desktop_worker_auth_valid"] is False
    assert result["metadata_status"] == "missing"
    assert ("http", "/readyz") in diagnostic and ("http", "/v1/workers") in diagnostic
    assert result["execution_authorized"] is False
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("failed_path", ["/readyz", "/v1/workers"])
def test_one_loopback_failure_does_not_suppress_other_components(diagnostic, monkeypatch, failed_path):
    original = p.read_loopback
    def partial(path):
        if path == failed_path:
            raise b.BootstrapError("orchestrator_readback_unavailable", PRIVATE)
        return original(path)
    monkeypatch.setattr(p, "read_loopback", partial)
    result = p.local_failure_inventory(expected_sha=HEAD, correlation_id=CORRELATION, preflight_state=BLOCK)
    failed_field = "readyz_status" if failed_path == "/readyz" else "workers_status"
    other_field = "workers_status" if failed_path == "/readyz" else "readyz_status"
    assert result[failed_field] == "unavailable"
    assert result[other_field] == "observed"
    assert result["watchdog_inventory_status"] == "observed"
    assert PRIVATE not in json.dumps(result)


def test_diagnostic_requires_source_before_any_local_fact(monkeypatch):
    def stale(sha):
        raise b.BootstrapError("source_sha_mismatch", "source_sha_mismatch")
    def forbidden(*args, **kwargs):
        pytest.fail("stale source cannot collect host facts")
    monkeypatch.setattr(p, "require_source", stale)
    monkeypatch.setattr(b, "validate_host", forbidden)
    monkeypatch.setattr(b, "find_gh", forbidden)
    monkeypatch.setattr(p, "read_loopback", forbidden)
    monkeypatch.setattr(w, "readonly_local_inventory", forbidden)
    with pytest.raises(b.BootstrapError) as raised:
        p.local_failure_inventory(expected_sha=HEAD, correlation_id=CORRELATION, preflight_state=BLOCK)
    assert raised.value.state == "source_sha_mismatch"


def inventory_receipt():
    return {
        "schema_version": 1, "kind": "orchestrator-runner-local-inventory",
        "source_sha": HEAD, "correlation_id": CORRELATION, "preflight_state": BLOCK,
        "read_only": True, **{key: False for key in h.INVENTORY_FALSE_FIELDS},
        "github_cli_status": "not_located", "github_owner_validation": "not_validated",
        "metadata_status": "missing", "runtime_listener_pid": 1234,
    }


def test_public_inventory_projects_only_closed_types_and_fields():
    raw = inventory_receipt()
    raw.update({
        "principal": PRIVATE, "stdout": PRIVATE, "path": PRIVATE,
        "task_state": True, "metadata_sha256": PRIVATE,
        "github_cli_status": PRIVATE, "loopback_ready": PRIVATE,
        "installed_source_sha": PRIVATE,
    })
    public = h.public_local_inventory(raw, sha=HEAD, correlation=CORRELATION, state=BLOCK)
    assert public is not None
    assert public["preflight_remains_blocked"] is True
    assert public["runtime_listener_pid"] == 1234
    assert public["task_state"] is None
    assert public["metadata_sha256"] is None
    assert public["github_cli_status"] == "unavailable"
    assert public["loopback_ready"] is None
    assert PRIVATE not in json.dumps(public)
    assert not {"principal", "stdout", "path"} & public.keys()


@pytest.mark.parametrize("field,value", [
    ("source_sha", "b" * 40), ("correlation_id", "wrong-correlation"),
    ("read_only", False), ("execution_authorized", True), ("schema_version", True),
])
def test_public_inventory_rejects_wrong_scope_or_effect_flags(field, value):
    raw = inventory_receipt()
    raw[field] = value
    assert h.public_local_inventory(raw, sha=HEAD, correlation=CORRELATION, state=BLOCK) is None


def test_gateway_emits_sanitized_inventory_and_keeps_preflight_failed(capsys):
    payload = {
        "ok": False, "state": BLOCK, "read_only": True,
        "execution_authorized": False, "registration_performed": False,
        "registration_token_requested": False, "local_inventory": inventory_receipt(),
        "stderr": PRIVATE,
    }
    event = {
        "action": "run", "risk": 1, "session_id": "fixed-session",
        "correlation_id": CORRELATION, "gateway_exit_code": 2, "command_exit_code": 2,
        "state_changed": False, "result": "command_failed",
        "before": {"head": HEAD}, "after": {"head": HEAD}, "stdout": json.dumps(payload),
    }
    completed = SimpleNamespace(returncode=2, stdout=json.dumps(event), stderr=PRIVATE)
    with pytest.raises(h.WorkflowBlocked, match="preflight_blocked:github_local_auth_required"):
        h.gateway_payload(completed, sha=HEAD, correlation=CORRELATION, session="fixed-session", negative=False)
    output = capsys.readouterr().out
    assert output.startswith("ORCHESTRATOR_LOCAL_INVENTORY:")
    assert PRIVATE not in output
    assert json.loads(output.split(":", 1)[1])["preflight_remains_blocked"] is True


@pytest.mark.parametrize("state", [BLOCK, "source_sha_mismatch"])
def test_probe_main_diagnostics_never_turn_failure_into_success(monkeypatch, capsys, state):
    def fail(**kwargs):
        raise b.BootstrapError(state, PRIVATE)
    calls = []
    def diagnostic(**kwargs):
        calls.append(kwargs)
        return inventory_receipt()
    monkeypatch.setattr(p, "preflight", fail)
    monkeypatch.setattr(p, "local_failure_inventory", diagnostic)
    assert p.main(["--expected-sha", HEAD, "--correlation-id", CORRELATION]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False and output["state"] == state
    assert bool(calls) is (state == BLOCK)
    assert PRIVATE not in json.dumps(output)
