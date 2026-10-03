import importlib.util
import json
from pathlib import Path
import pytest

SPEC = importlib.util.spec_from_file_location("dev_preflight", Path(__file__).parents[1] / "scripts" / "reqsys_self_hosted_dev_preflight.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

def test_wrong_host_does_not_call_docker(monkeypatch):
    monkeypatch.setattr(module.socket, "gethostname", lambda: "wrong-host")
    monkeypatch.setattr(module, "docker", lambda _: pytest.fail("docker must not execute"))
    with pytest.raises(RuntimeError, match="FIXED_HOST_OR_RUNNER_MISMATCH"):
        module.collect()

def test_docker_failure_does_not_return_stderr(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
        stderr = "sensitive connection details"
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: Result())
    assert module.docker(["version"]) == (False, "")

def test_backup_probe_never_reads_password(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    root = tmp_path / "ReqSys" / "MigrationBackups" / "20261002-1912"
    root.mkdir(parents=True)
    (root / "password.txt").write_text("private")
    monkeypatch.setattr(Path, "read_text", lambda *a, **k: pytest.fail("must not read files"))
    assert module.backup_facts()["validated_sqlite_present"] is False
