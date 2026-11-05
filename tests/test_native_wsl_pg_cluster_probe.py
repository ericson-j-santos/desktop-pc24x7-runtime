"""Contratos sintéticos sem acesso ao host, WSL, banco ou credenciais."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import json
import sys
import types

import pytest

SOURCE = Path(__file__).parents[1] / "scripts" / "native_wsl_pg_cluster_probe.py"
SPEC = importlib.util.spec_from_file_location("native_wsl_pg_cluster_probe", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def provenance():
    return {"host_alias": "authorized-primary", "source_sha": "a" * 40,
            "rules_sha": "b" * 40, "run_id": "41723787911",
            "correlation_id": "dedicated-runner-41723787911-1",
            "run_attempt": 1, "runner_version": "2.338.2"}


def clusters(status="online", version="15", name="main", port=5432):
    return f"{version} {name} {port} {status} postgres /var/lib/postgresql/15/main /var/log/postgresql/log\n"


def test_healthy_cluster_does_not_prove_database_identity_or_network_safety():
    result = probe.assemble(provenance(), clusters(), 0)
    assert result["cluster_ready"] is True
    assert result["read_only"] is True
    assert result["database_identity_verified"] is False
    assert result["database_target_qualified"] is False
    assert result["network_isolation_verified"] is False
    assert result["ready_for_installation"] is False
    assert "/var/lib/" not in json.dumps(result)
    assert result == probe.assemble(provenance(), clusters(), 0)


@pytest.mark.parametrize("raw,code", [
    (clusters(status="down"), 2),
    (clusters(status="online,recovery"), 0),
    (clusters(port=5433), 0),
    (clusters(version="16"), 0),
    ("", 0),
    (clusters(), 1),
    (clusters(), 3),
])
def test_no_false_cluster_ready(raw, code):
    report = probe.assemble(provenance(), raw, code)
    assert report["cluster_ready"] is False
    assert report["ready_for_installation"] is False


@pytest.mark.parametrize("raw", [
    clusters() * 2,
    "15 main NOTPORT online postgres /var/lib/a /var/log/a",
    "15 main 5432 online postgres /var/lib/a",
    "15 main 65536 online postgres /var/lib/a /var/log/a",
    "15 main 5432 changed postgres /var/lib/a /var/log/a",
    clusters() * 17,
    "x" * 8193,
    "15 main 5432 online\n",
])
def test_fail_closed_on_corrupt_or_duplicate_metadata(raw):
    with pytest.raises(probe.ProbeBlocked):
        probe.assemble(provenance(), raw, 0)


def test_false_success_mutations_are_rejected():
    report = probe.assemble(provenance(), clusters(), 0)
    for field, value in (("database_target_qualified", True),
                         ("ready_for_installation", True),
                         ("read_only", False),
                         ("cluster_ready", False),
                         ("cluster_port", 5433),
                         ("source_sha", "0")):
        bad = deepcopy(report)
        bad[field] = value
        with pytest.raises(probe.ProbeBlocked):
            probe.validate(bad)


def test_ambiguous_return_code_not_accepted():
    for code in (True, -1, 4, "0", None):
        with pytest.raises(probe.ProbeBlocked):
            probe.readiness(code)


def test_provenance_gate_runs_before_commands(monkeypatch):
    called = []
    fake_base = types.ModuleType("native_windows_pg_inventory")
    class InventoryBlocked(Exception):
        pass
    fake_base.InventoryBlocked = InventoryBlocked
    def verify(env, host, platform):
        if env != {"valid": True}:
            raise InventoryBlocked("blocked")
        return provenance()
    fake_base.provenance = verify
    fake_wsl = types.ModuleType("native_wsl_pg_qualification")
    fake_wsl.QualificationBlocked = type("QualificationBlocked", (Exception,), {})
    class FakeWsl:
        def _run(self, *args, **kwargs):
            called.append((args, kwargs))
            if args[0] == "/usr/bin/pg_lsclusters":
                return 0, clusters()
            assert args == ("/usr/bin/pg_isready", "-h", "127.0.0.1", "-p", "5432", "-t", "3")
            assert kwargs == {"accepted": (0, 1, 2, 3)}
            return 0, "127.0.0.1:5432 - accepting connections"
    fake_wsl.WslProbe = FakeWsl
    monkeypatch.setitem(sys.modules, "native_windows_pg_inventory", fake_base)
    monkeypatch.setitem(sys.modules, "native_wsl_pg_qualification", fake_wsl)
    with pytest.raises(probe.ProbeBlocked, match="origin_unverified"):
        probe.collect({}, "wrong", "win32")
    assert called == []
    success = probe.collect({"valid": True}, "DESKTOP-PDQK954", "win32")
    assert success["cluster_ready"] is True
    assert len(called) == 2
    assert called[0][0] == ("/usr/bin/pg_lsclusters", "-h")


def test_no_mutating_or_arbitrary_command_interface():
    text = SOURCE.read_text(encoding="utf-8")
    for item in ("shell=True", "sudo ", "psql ", "postgresql://",
                 "DATABASE_URL", "systemctl restart", "systemctl enable",
                 "docker compose", "subprocess.Popen(", "subprocess.run(",
                 "apt-get", "DROP DATABASE", "postgresql.conf"):
        assert item not in text
    assert '"/usr/bin/pg_lsclusters", "-h"' in text
    assert '"/usr/bin/pg_isready", "-h", "127.0.0.1"' in text
