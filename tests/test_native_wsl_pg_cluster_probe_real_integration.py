"""Integração da sonda com os módulos reais da main (sem host, DB ou WSL)."""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import sys

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import native_windows_pg_inventory as inventory
import native_wsl_pg_qualification as wsl

SOURCE = Path(__file__).parents[1] / "scripts" / "native_wsl_pg_cluster_probe.py"
SPEC = importlib.util.spec_from_file_location("probe_runtime134_real", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def valid_env():
    return dict(zip(inventory.CI_KEYS, (
        "true", inventory.EXPECTED_REPOSITORY, "a" * 40, "b" * 40,
        inventory.EXPECTED_RUNNER, "Windows", "X64", "41723787911", "1",
        "ericson-j-santos", "workflow_dispatch", "2.338.2",
        "true", "true", "true", datetime.now(timezone.utc).isoformat(),
    )))


def runner_factory(records, *, cluster_return=0, cluster_output=None, ready_return=0):
    if cluster_output is None:
        cluster_output = "15 main 5432 online postgres /var/lib/postgresql/15/main /var/log/postgresql/postgresql.log\n"
    expected = {
        ("wsl.exe", "--exec", "/usr/bin/pg_lsclusters", "-h"):
        (cluster_return, cluster_output),
        ("wsl.exe", "--exec", "/usr/bin/pg_isready", "-h", "127.0.0.1", "-p", "5432", "-t", "3"):
        (ready_return, "ready data must never reach evidence"),
    }
    def fake_runner(command, **kwargs):
        records.append((tuple(command), kwargs))
        assert tuple(command) in expected, "execução fora do conjunto fixo"
        assert kwargs["shell"] is False and kwargs["check"] is False
        assert kwargs["capture_output"] is True and kwargs["timeout"] == 20
        code, body = expected[tuple(command)]
        return subprocess.CompletedProcess(command, code, stdout=body, stderr="")
    return wsl.WslProbe(fake_runner)


def test_end_to_end_readonly_two_fixed_commands_real_modules():
    records=[]
    value=probe.collect(valid_env(), inventory.EXPECTED_HOST,"win32",lambda: runner_factory(records))
    assert [row[0][2] for row in records] == ["/usr/bin/pg_lsclusters", "/usr/bin/pg_isready"]
    assert value["cluster_ready"] is True
    assert value["cluster_present"] is True
    assert value["database_identity_verified"] is False
    assert value["network_isolation_verified"] is False
    assert value["backup_restore_verified"] is False
    assert value["ready_for_installation"] is False
    assert "/var/lib/postgresql" not in str(value)
    assert "ready data" not in str(value)


def test_unavailable_pg_lsclusters_fails_before_ready_probe():
    records=[]
    with pytest.raises(probe.ProbeBlocked, match="fixed_probe_failed"):
        probe.collect(valid_env(), inventory.EXPECTED_HOST,"win32",
                      lambda: runner_factory(records,cluster_return=127))
    assert len(records)==1


def test_pg_isready_refused_is_measured_not_ready():
    records=[]
    value=probe.collect(valid_env(), inventory.EXPECTED_HOST,"win32",
                        lambda: runner_factory(records,ready_return=2))
    assert len(records)==2
    assert value["cluster_ready"] is False
    assert value["pg_isready_state"]=="no_response"


def test_real_provenance_blocks_without_invoking_wsl():
    called=[]
    env=valid_env();env["GITHUB_SHA"]="bad"
    with pytest.raises(probe.ProbeBlocked, match="origin_unverified"):
        probe.collect(env, inventory.EXPECTED_HOST,"win32",lambda: called.append(1))
    assert not called


def test_forged_systemd_evidence_never_upgrades_identity():
    records=[]
    value=probe.collect(valid_env(), inventory.EXPECTED_HOST,"win32",lambda: runner_factory(records))
    for flag in ("database_identity_verified","database_target_qualified","backup_restore_verified","ready_for_installation"):
        value[flag]=True
        with pytest.raises(probe.ProbeBlocked, match="false_success"):
            probe.validate(value)
        value[flag]=False
