"""Native WSL systemd detail probe tests; no physical host or WSL invocation."""
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import subprocess
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "native_wsl_systemd_failure_details_probe",
    SCRIPTS / "native_wsl_systemd_failure_details_probe.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def valid_env():
    base = module.wsl.base
    return dict(zip(base.CI_KEYS, (
        "true", base.EXPECTED_REPOSITORY, "a" * 40, "b" * 40,
        base.EXPECTED_RUNNER, "Windows", "X64", "41714342405", "1",
        "ericson-j-santos", "workflow_dispatch", "2.338.2",
        "true", "true", "true", datetime.now(timezone.utc).isoformat(),
    )))


def show(unit, **overrides):
    values = {
        "Id": unit,
        "LoadState": "loaded",
        "ActiveState": "failed",
        "SubState": "failed",
        "Result": "exit-code",
        "ExecMainCode": "exited",
        "ExecMainStatus": "1",
        "ConditionResult": "success",
        "AssertResult": "success",
    }
    values.update(overrides)
    return "\n".join(f"{key}={values[key]}" for key in module.PROPERTIES) + "\n"


class FakeProbe:
    failed = (
        "● postgresql@15-main.service loaded failed failed summary\n"
        "custom-agent.service loaded failed failed summary\n"
    )

    def __init__(self):
        self.calls = []

    def _run(self, *args):
        self.calls.append(args)
        if args[1] == "--failed":
            return 0, self.failed
        assert args[1] == "show"
        return 0, show(args[2])


def test_collect_returns_bounded_unit_names_and_cause_fields():
    probe = FakeProbe()
    result = module.collect(valid_env(), module.wsl.base.EXPECTED_HOST, "win32",
                            lambda: probe)
    assert result["status"] == "measured"
    assert result["failed_unit_count"] == 2
    assert result["failed_units"][0]["unit"] == "postgresql@15-main.service"
    assert result["failed_units"][0]["category"] == "postgresql"
    assert result["failed_units"][0]["properties"]["Result"] == "exit-code"
    assert result["failed_units"][1]["unit"] == "custom-agent.service"
    assert result["failed_units"][1]["category"] == "other"
    assert len(probe.calls) == 3
    assert result["cause_proven"] is False
    assert result["systemd_repaired"] is False
    assert result["backup_created"] is False


def test_parse_show_output_rejects_duplicate_unknown_or_unbounded_values():
    good = show("postgresql.service")
    with pytest.raises(module.ProbeBlocked):
        module.parse_show_output("postgresql.service", good + "Result=timeout\n")
    with pytest.raises(module.ProbeBlocked):
        module.parse_show_output(
            "postgresql.service",
            good.replace("Result=exit-code", "Unknown=value"),
        )
    with pytest.raises(module.ProbeBlocked):
        module.parse_show_output(
            "postgresql.service",
            good.replace("Result=exit-code", "Result=bad\nResult=" + "x" * 161),
        )


def test_parse_failed_rows_rejects_duplicate_or_invalid_units():
    with pytest.raises(module.ProbeBlocked, match="duplicate_failed_unit"):
        module.parse_failed_rows(
            "foo.service loaded failed failed\nfoo.service loaded failed failed\n"
        )
    with pytest.raises(module.ProbeBlocked):
        module.parse_failed_rows("password.secret loaded failed failed\n")


def test_fixed_probe_never_uses_mutating_or_shell_commands():
    source = (SCRIPTS / "native_wsl_systemd_failure_details_probe.py").read_text(
        encoding="utf-8"
    )
    for denied in (
        "subprocess.Popen(", "subprocess.run(", "os.system(", "shell=True",
        "apt-get", "docker compose", "systemctl restart", "systemctl enable",
        "Start-Process", "postgresql://",
    ):
        assert denied not in source
    commands = []
    def runner(argv, **kwargs):
        commands.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    wsl = module.wsl.WslProbe(runner)
    wsl._run("/usr/bin/systemctl", "show", "postgresql.service")
    assert commands[0][0] == [
        "wsl.exe", "--exec", "/usr/bin/systemctl", "show", "postgresql.service"
    ]
    assert commands[0][1]["shell"] is False
    assert commands[0][1]["timeout"] == 20


def test_readback_rejects_forged_category_and_duplicate_unit():
    from copy import deepcopy

    original = module.collect(
        valid_env(), module.wsl.base.EXPECTED_HOST, "win32", FakeProbe
    )
    forged = deepcopy(original)
    forged["failed_units"][0]["category"] = "network"
    with pytest.raises(module.ProbeBlocked, match="unit_category_mismatch"):
        module.validate(forged)

    duplicated = deepcopy(original)
    duplicated["failed_units"].append(deepcopy(duplicated["failed_units"][0]))
    duplicated["failed_unit_count"] += 1
    with pytest.raises(module.ProbeBlocked, match="duplicate_failed_unit"):
        module.validate(duplicated)

    assert module.validate(original) is None
    assert module.validate(original) is None  # idempotent replay


def test_false_success_fields_are_blocked():
    probe = FakeProbe()
    result = module.collect(valid_env(), module.wsl.base.EXPECTED_HOST, "win32",
                            lambda: probe)
    result["cause_proven"] = True
    with pytest.raises(module.ProbeBlocked):
        module.validate(result)
