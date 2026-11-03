"""Targeted WSL systemd diagnosis tests; no physical host or WSL invocation."""
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import json
import subprocess
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "native_wsl_systemd_targeted_diagnosis_probe",
    SCRIPTS / "native_wsl_systemd_targeted_diagnosis_probe.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def valid_env():
    base = module.wsl.base
    return dict(zip(base.CI_KEYS, (
        "true", base.EXPECTED_REPOSITORY, "a" * 40, "b" * 40,
        base.EXPECTED_RUNNER, "Windows", "X64", "41716356192", "1",
        "ericson-j-santos", "workflow_dispatch", "2.338.2",
        "true", "true", "true", datetime.now(timezone.utc).isoformat(),
    )))


def show(unit, **overrides):
    values = {
        key: "loaded" for key in module.DIAG_PROPERTIES
    }
    values.update({
        "Id": unit,
        "ActiveState": "failed",
        "SubState": "failed",
        "Result": "protocol",
        "ExecMainCode": "exited",
        "ExecMainStatus": "1",
        "UnitFileState": "enabled",
        "NRestarts": "2",
        "StatusText": "failed",
        "LoadError": "",
        "JobResult": "done",
        "FragmentPath": "/lib/systemd/system/test.service",
        "DropInPaths": "",
    })
    values.update(overrides)
    return "\n".join(f"{key}={values[key]}" for key in module.DIAG_PROPERTIES) + "\n"


def journal(unit):
    return "\n".join(json.dumps({
        "_SYSTEMD_UNIT": unit,
        "MESSAGE": message,
    }) for message in (
        "authentication failed; protocol error",
        "process exited with status=1",
    )) + "\n"


class FakeProbe:
    failed = (
        "● postgresql@15-main.service loaded failed failed summary\n"
        "fail2ban.service loaded failed failed summary\n"
    )

    def __init__(self):
        self.calls = []

    def _run(self, *args):
        self.calls.append(args)
        if args[1] == "--failed":
            return 0, self.failed
        assert args[1] == "show" or args[0] == "/usr/bin/journalctl"
        if args[0] == "/usr/bin/journalctl":
            return 0, journal(args[2])
        return 0, show(args[2])


def test_collect_returns_sanitized_targeted_evidence():
    probe = FakeProbe()
    result = module.collect(
        valid_env(), module.wsl.base.EXPECTED_HOST, "win32", lambda: probe
    )
    assert result["status"] == "measured"
    assert result["journal_read"] is True
    assert result["failed_unit_count"] == 2
    assert result["failed_units"][0]["unit"] == "postgresql@15-main.service"
    assert result["failed_units"][0]["journal"]["evidence_codes"] == [
        "authentication_failed", "process_exit", "protocol_error"
    ]
    assert result["failed_units"][1]["unit"] == "fail2ban.service"
    assert len(probe.calls) == 5
    serialized = json.dumps(result)
    assert "authentication failed; protocol error" not in serialized
    assert result["cause_proven"] is False
    assert result["systemd_repaired"] is False
    assert result["backup_created"] is False


def test_parse_journal_rejects_cross_unit_and_raw_invalid_data():
    with pytest.raises(module.ProbeBlocked, match="journal_unit_mismatch"):
        module.parse_journal(
            "postgresql.service",
            json.dumps({"_SYSTEMD_UNIT": "other.service", "MESSAGE": "timeout"}),
        )
    with pytest.raises(module.ProbeBlocked, match="journal_schema"):
        module.parse_journal("postgresql.service", "not-json\n")


def test_parse_show_output_reports_fixed_missing_property():
    raw = show("postgresql@15-main.service")
    raw = "\n".join(
        line for line in raw.splitlines() if not line.startswith("DropInPaths=")
    ) + "\n"
    with pytest.raises(
        module.ProbeBlocked, match="show_output_missing_DropInPaths"
    ):
        module.parse_show_output("postgresql@15-main.service", raw)


def test_parse_show_output_treats_job_result_as_optional():
    raw = show("postgresql@15-main.service")
    raw = "\n".join(
        line for line in raw.splitlines() if not line.startswith("JobResult=")
    ) + "\n"
    parsed = module.parse_show_output("postgresql@15-main.service", raw)
    assert parsed["JobResult"] == ""


def test_collect_preserves_parser_block_reason():
    class BrokenProbe(FakeProbe):
        def _run(self, *args):
            if args[0] == "/usr/bin/journalctl":
                return 0, "not-json\\n"
            return super()._run(*args)

    with pytest.raises(module.ProbeBlocked, match="journal_schema"):
        module.collect(
            valid_env(), module.wsl.base.EXPECTED_HOST, "win32", BrokenProbe
        )


def test_fixed_probe_never_uses_mutating_or_unbounded_commands():
    source = (
        SCRIPTS / "native_wsl_systemd_targeted_diagnosis_probe.py"
    ).read_text(encoding="utf-8")
    for denied in (
        "subprocess.Popen(", "subprocess.run(", "os.system(", "shell=True",
        "apt-get", "docker compose", "systemctl restart", "systemctl enable",
        "systemctl reset-failed", "journalctl --vacuum", "Start-Process",
        "postgresql://",
    ):
        assert denied not in source
    commands = []

    def runner(argv, **kwargs):
        commands.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    wsl = module.wsl.WslProbe(runner)
    wsl._run(
        "/usr/bin/journalctl", "--unit", "fail2ban.service",
        "--no-pager", "--output=json", "--lines", "24", "--quiet", "--utc"
    )
    assert commands[0][0] == [
        "wsl.exe", "--exec", "/usr/bin/journalctl", "--unit", "fail2ban.service",
        "--no-pager", "--output=json", "--lines", "24", "--quiet", "--utc"
    ]
    assert commands[0][1]["shell"] is False
    assert commands[0][1]["timeout"] == 20


def test_blocked_report_exposes_only_fixed_reason():
    assert module.blocked_report("journal_schema") == {
        "contract": module.CONTRACT,
        "reason": "journal_schema",
        "status": "blocked",
    }
    assert module.blocked_report("raw host output") == {
        "contract": module.CONTRACT,
        "reason": "fixed_probe_failed",
        "status": "blocked",
    }


def test_false_success_fields_are_blocked():
    probe = FakeProbe()
    result = module.collect(
        valid_env(), module.wsl.base.EXPECTED_HOST, "win32", lambda: probe
    )
    result["cause_proven"] = True
    with pytest.raises(module.ProbeBlocked):
        module.validate(result)
