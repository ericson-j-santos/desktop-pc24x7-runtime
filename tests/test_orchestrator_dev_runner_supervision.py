from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("additional_watchdog_test", ROOT / "scripts/desktop_control_plane_watchdog.py")
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


@pytest.fixture
def registered(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    home = local / "EngineeringOrchestratorDEV" / "GitHubRunner"
    (home / "bin").mkdir(parents=True)
    (home / "run.cmd").write_text("not executed")
    (home / "bin" / "Runner.Listener.exe").write_bytes(b"not executed")
    (home / ".runner").write_text(json.dumps({
        "agentId": 21, "agentName": "DESKTOP-PDQK954-orchestrator-dev",
        "gitHubUrl": "https://github.com/ericson-j-santos/reqsys-engineering-orchestrator"}))
    (home / ".credentials").write_text("private-never-read")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(m.socket, "gethostname", lambda: "DESKTOP-PDQK954")
    return home


def test_only_fixed_profile_and_binding_are_admitted(registered, monkeypatch):
    assert m.additional_orchestrator_runner_home({}) is None
    assert m.additional_orchestrator_runner_home({"additional_runner_profiles": ["orchestrator-dev"]}) == registered
    for profiles in (["runtime"], ["orchestrator-dev", "orchestrator-dev"], "orchestrator-dev"):
        with pytest.raises(m.WatchdogError):
            m.additional_orchestrator_runner_home({"additional_runner_profiles": profiles})
    data = json.loads((registered / ".runner").read_text())
    for key, value in (("agentId", 22), ("gitHubUrl", "https://github.com/another/repo"),
                       ("agentName", "DESKTOP-PDQK954-runtime")):
        changed = dict(data)
        changed[key] = value
        (registered / ".runner").write_text(json.dumps(changed))
        with pytest.raises(m.WatchdogError):
            m.additional_orchestrator_runner_home({"additional_runner_profiles": ["orchestrator-dev"]})


def test_runtime_credentials_are_never_read(registered, monkeypatch):
    original = Path.open
    def guarded(path, *args, **kwargs):
        if path.name == ".credentials":
            pytest.fail("runtime credentials must not be read")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    assert m.additional_orchestrator_runner_home({"additional_runner_profiles": ["orchestrator-dev"]}) == registered


def test_listener_receives_only_windows_runtime_environment():
    env = {"SystemRoot": r"C:\Windows", "LOCALAPPDATA": r"C:\Users\test\AppData\Local",
           "Path": r"C:\Windows\System32", "GH_TOKEN": "private", "GITHUB_TOKEN": "private",
           "PR_REMEDIATOR_GITHUB_TOKEN": "private", "RUNNER_TRACKING_ID": "private",
           "AZURE_CLIENT_SECRET": "private", "ACTIONS_RUNNER_INPUT_TOKEN": "private"}
    observed = m.orchestrator_runner_environment(env)
    assert observed == {key: env[key] for key in ("SystemRoot", "LOCALAPPDATA", "Path")}
    assert "private" not in str(observed)


def test_existing_cycle_supervises_additional_runner_and_never_calls_disabled_rdc(registered, tmp_path, monkeypatch):
    primary = tmp_path / "primary"
    primary.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    release = tmp_path / "release"
    (release / "scripts").mkdir(parents=True)
    (release / "scripts" / m.RDC_RECOVERY_SCRIPT).write_text("must not run")
    monkeypatch.setattr(m, "require_windows_desktop", lambda: "DESKTOP-PDQK954")
    monkeypatch.setattr(m, "validate_runner_home", lambda path: path)
    calls = []
    def start(home, log):
        calls.append(home)
        return {"status": "process_running", "started": False}
    monkeypatch.setattr(m, "start_runner", start)
    monkeypatch.setattr(m, "recover_rdc", lambda **kwargs: pytest.fail("RDC must not be used"))
    metadata = {"runtime_root": str(runtime), "release_root": str(release),
                "runner_home": str(primary), "python_executable": sys.executable,
                "source_sha": "a" * 40, "additional_runner_profiles": ["orchestrator-dev"],
                "rdc_recovery_enabled": False}
    result = m.cycle(metadata)
    assert calls == [primary, registered]
    assert result["ok"] is True and result["primary_runner_recovery_ok"] is True
    assert result["additional_runners"]["orchestrator-dev"]["runner_id"] == 21
    assert result["rdc_required"] is False and result["rdc"]["reason"] == "disabled_by_owner"
    assert metadata["runner_home"] == str(primary)
    def failed(home, log):
        if home == registered:
            raise m.WatchdogError("controlled")
        return {"status": "process_running"}
    monkeypatch.setattr(m, "start_runner", failed)
    assert m.cycle(metadata)["ok"] is False
