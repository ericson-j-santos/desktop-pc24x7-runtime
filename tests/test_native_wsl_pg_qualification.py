"""Synthetic controls only; no test starts WSL."""
import importlib.util
import subprocess
import sys
from pathlib import Path


SCRIPTS = Path(__file__).parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SOURCE = SCRIPTS / "native_wsl_pg_qualification.py"
SPEC = importlib.util.spec_from_file_location("native_wsl_pg_qualification", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def valid_env():
    base = module.base
    return dict(zip(base.CI_KEYS, (
        "true", base.EXPECTED_REPOSITORY, "a" * 40, "b" * 40,
        base.EXPECTED_RUNNER, "Windows", "X64", "123", "1",
        "ericson-j-santos", "workflow_dispatch", "2.338.0", "true", "true", "true",
        base.datetime.now(base.timezone.utc).isoformat(),
    )))


class FakeProbe:
    def init_system(self): return "systemd"
    def systemd_state(self): return "degraded"
    def wsl_conf_systemd(self): return True
    def filesystem(self, alias, path):
        available = 7 if alias == "root" else (7 if alias == "windows-volume-1" else 1425)
        return {"alias": alias, "present": True,
                "filesystem": "ext4" if alias == "root" else "9p",
                "size_gib_floor": 49 if alias == "root" else 1861,
                "available_gib_floor": available,
                "backup_capacity_candidate": alias == "windows-volume-2"}
    def executable(self, path): return False
    def postgresql_unit(self):
        return {"load_state": "not-found", "active_state": "inactive",
                "enable_state": "not-found"}
    def listeners_5432(self): return []


def test_measured_start_does_not_claim_target_qualified():
    value = module.collect(valid_env(), module.base.EXPECTED_HOST, "win32", FakeProbe)
    assert value["linux_started"] is True
    assert value["systemd_verified"] is True
    assert value["mounts"][2]["backup_capacity_candidate"] is True
    for key in ("storage_durability_verified", "restart_verified",
                "backup_destination_selected", "database_target_qualified",
                "ready_for_installation", "database_connected", "configuration_changed",
                "packages_installed", "network_changed"):
        assert value[key] is False


def test_provenance_rejected_before_wsl_probe():
    env = valid_env()
    env["RUNNER_NAME"] = "other"
    called = False
    def factory():
        nonlocal called
        called = True
        return FakeProbe()
    try:
        module.collect(env, module.base.EXPECTED_HOST, "win32", factory)
    except module.base.InventoryBlocked:
        pass
    else:
        raise AssertionError("provenance must fail closed")
    assert called is False


def test_wsl_runner_uses_fixed_exec_without_shell():
    calls = []
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="systemd\n", stderr="")
    assert module.WslProbe(runner).init_system() == "systemd"
    assert calls[0][0] == ["wsl.exe", "--exec", "/bin/cat", "/proc/1/comm"]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 20


def test_df_parser_and_missing_mount_are_bounded():
    responses = iter(((0, "ext4\n"), (0, "Size Avail\n53687091200 7516192768\n")))
    probe = module.WslProbe()
    probe._run = lambda *args, **kwargs: next(responses)
    row = probe.filesystem("root", "/")
    assert row["size_gib_floor"] == 50
    assert row["available_gib_floor"] == 7
    assert row["backup_capacity_candidate"] is False

    probe._run = lambda *args, **kwargs: (1, "")
    assert probe.filesystem("windows-volume-2", "/mnt/d")["present"] is False


def test_listener_output_is_reduced_to_family_and_bind():
    probe = module.WslProbe()
    probe._run = lambda *args, **kwargs: (0, "LISTEN 0 10 127.0.0.1:5432 0.0.0.0:*\n"
                                             "LISTEN 0 10 [::]:5432 [::]:*\n"
                                             "LISTEN 0 10 127.0.0.1:8000 0.0.0.0:*")
    assert probe.listeners_5432() == [
        {"family": "ipv4", "bind": "loopback"},
        {"family": "ipv6", "bind": "wildcard"},
    ]


def test_source_has_no_install_connection_or_termination_capability():
    raw = SOURCE.read_text(encoding="utf-8")
    for forbidden in ("apt-get", "aptitude", "dnf", "yum", "pacman", "psql -", "--terminate", "--shutdown",
                      "shell=True", "postgresql://", "DATABASE_URL", "subprocess.Popen"):
        assert forbidden not in raw
    assert '"wsl.exe", "--exec"' in raw
    assert "database_connected\": False" in raw
