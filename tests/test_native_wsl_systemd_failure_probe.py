"""Native WSL systemd probe tests; no physical host or WSL invocation."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import subprocess
import sys
import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "native_wsl_systemd_failure_probe",
    SCRIPTS / "native_wsl_systemd_failure_probe.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def valid_env():
    base = module.wsl.base
    return dict(zip(base.CI_KEYS, (
        "true", base.EXPECTED_REPOSITORY, "a" * 40, "b" * 40,
        base.EXPECTED_RUNNER, "Windows", "X64", "41698530586", "1",
        "ericson-j-santos", "workflow_dispatch", "2.338.2",
        "true", "true", "true", datetime.now(timezone.utc).isoformat(),
    )))


class FakeProbe:
    calls = 0
    output = "● postgresql@15-main.service loaded failed failed summary\n"

    def _run(self, *args):
        self.calls += 1
        assert args == ("/usr/bin/systemctl", "--failed", "--no-legend",
                        "--no-pager", "--plain")
        return 0, self.output


def test_postgresql_failure_classified_no_unit_names():
    result = module.collect(valid_env(), module.wsl.base.EXPECTED_HOST,
                            "win32", FakeProbe)
    assert result["status"] == "measured"
    assert result["failed_unit_count"] == 1
    assert result["categories"]["postgresql"] == 1
    assert result["first_category"] == "postgresql"
    assert "postgresql@15-main" not in str(result)
    for key in ("cause_proven", "postgresql_modified", "systemd_repaired",
                "backup_created", "deployment_performed", "ready_for_installation"):
        assert result[key] is False


def test_multiple_categories_are_bounded_and_sanitized():
    raw = ("● networking.service loaded failed failed description\n"
           "mnt-backup.mount loaded failed failed more-description\n"
           "foo.service loaded failed failed arbitrary\n")
    assert module.parse_failed_units(raw) == {
        "postgresql": 0, "network": 1, "mount": 1, "wsl": 0, "other": 1,
    }


def test_empty_list_does_not_prove_systemd_recovered():
    class Empty(FakeProbe):
        output = ""
    result = module.collect(valid_env(), module.wsl.base.EXPECTED_HOST,
                            "win32", Empty)
    assert result["first_category"] == "none_observed"
    assert result["cause_proven"] is False
    assert result["ready_for_installation"] is False


@pytest.mark.parametrize("raw", [
    "nonsense",
    "UNIT LOAD ACTIVE SUB DESCRIPTION",
    "foo.service loaded active running description",
    "foo.service loaded failed failed\n" + "bar.service loaded failed failed\n" * 33,
    "password.secret loaded failed failed",
    "foo.service loaded failed failed\nbar.timer loaded failed active",
    "not-a-unit loaded failed failed",
])
def test_invalid_or_excessive_output_rejected(raw):
    with pytest.raises(module.ProbeBlocked):
        module.parse_failed_units(raw)


def test_wrong_runner_and_stale_authorization_block_before_probe():
    class Recorder(FakeProbe):
        calls = 0
    data = valid_env()
    data["RUNNER_NAME"] = "DESKTOP-RP23OGS-runtime"
    with pytest.raises(module.ProbeBlocked):
        module.collect(data, module.wsl.base.EXPECTED_HOST, "win32", Recorder)
    data = valid_env()
    data["INVENTORY_ADMITTED_AT"] = "2000-01-01T00:00:00Z"
    with pytest.raises(module.ProbeBlocked):
        module.collect(data, module.wsl.base.EXPECTED_HOST, "win32", Recorder)
    assert Recorder.calls == 0


def test_command_is_fixed_wsl_exec_and_never_uses_shell():
    commands = []
    def runner(argv, **kwargs):
        commands.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0,
            stdout="● foo.service loaded failed failed generic\n", stderr="")
    wsl = module.wsl.WslProbe(runner)
    code, value = wsl._run("/usr/bin/systemctl", "--failed", "--no-legend",
                           "--no-pager", "--plain")
    assert code == 0
    assert "foo.service" in value
    assert commands[0][0] == ["wsl.exe", "--exec", "/usr/bin/systemctl",
                               "--failed", "--no-legend", "--no-pager", "--plain"]
    assert commands[0][1]["shell"] is False
    assert commands[0][1]["timeout"] == 20


def test_repeat_is_deterministic_without_mutation():
    first = module.collect(valid_env(), module.wsl.base.EXPECTED_HOST, "win32",
                           FakeProbe)
    assert first == deepcopy(first)
    assert first["deployment_performed"] is False


def test_fake_positive_report_fails_validation():
    report = module.collect(valid_env(), module.wsl.base.EXPECTED_HOST, "win32",
                            FakeProbe)
    report["cause_proven"] = True
    with pytest.raises(module.ProbeBlocked):
        module.validate(report)
    report["cause_proven"] = False
    report["categories"]["postgresql"] = "1"
    with pytest.raises(module.ProbeBlocked):
        module.validate(report)


def test_no_unrestricted_or_mutating_command_path():
    source = (SCRIPTS / "native_wsl_systemd_failure_probe.py").read_text(
        encoding="utf-8")
    for denied in ("subprocess.Popen(", "subprocess.run(", "os.system(",
                   "shell=True", "apt-get", "docker compose", "systemctl restart",
                   "Start-Process", "postgresql://"):
        assert denied not in source
