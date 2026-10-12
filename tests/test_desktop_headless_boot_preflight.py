"""Positive/negative controls for the fixed, sanitized Windows pre-boot preflight."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest

SCRIPT = Path(__file__).resolve().parents[1]/"scripts"/"desktop_headless_boot_preflight.py"
spec=importlib.util.spec_from_file_location("headless_preflight",SCRIPT)
assert spec and spec.loader
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

XML_TEMPLATE="""<?xml version="1.0"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><BootTrigger><Enabled>{boot}</Enabled></BootTrigger></Triggers>
<Principals><Principal><LogonType>{logon}</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings><Enabled>{enabled}</Enabled></Settings><Actions><Exec><Command>secret-do-not-output</Command></Exec></Actions>
</Task>"""

def task(logon="S4U",boot="true",enabled="true"):
    return probe.xmltask(XML_TEMPLATE.format(logon=logon,boot=boot,enabled=enabled))

def test_boot_and_s4u_positive():
    got=task()
    assert got["exists"] and got["boot_trigger_enabled"] and got["unattended_logon_type"] and got["highest_runlevel"]
    assert "secret" not in str(got)

def test_logon_only_disabled_and_password_negative():
    assert not task(boot="false")["boot_trigger_enabled"]
    assert not task(enabled="false")["task_enabled"]
    assert not task(logon="InteractiveToken")["unattended_logon_type"]
    assert not task(logon="Password")["unattended_logon_type"]

def test_task_action_secret_never_emitted():
    got=task()
    assert "Actions" not in str(got) and "secret-do-not-output" not in str(got)

def test_invalid_xml_fail_closed():
    with pytest.raises(probe.Blocked):
        probe.xmltask("<Registry/>")
    with pytest.raises(Exception):
        probe.xmltask("<Task")

def test_query_rejects_unknown_name():
    with pytest.raises(probe.Blocked):
        probe.querytask(r"\NotAllowed\Another", run=lambda *a,**k:None)

def test_query_task_args_readonly_and_bounded(monkeypatch):
    captured={}
    def fake(args,**kwargs):
        captured.update({"args":args,"kwargs":kwargs})
        return SimpleNamespace(returncode=0,stdout=XML_TEMPLATE.format(boot="true",logon="S4U",enabled="true"))
    got=probe.querytask(probe.TASKS["runtime_watchdog"],run=fake)
    assert got["boot_trigger_enabled"]
    assert captured["args"][1:]==["/Query","/TN",probe.TASKS["runtime_watchdog"],"/XML"]
    assert captured["kwargs"]["shell"] is False and captured["kwargs"]["timeout"]<=15

def test_query_failure_not_absence_proof():
    p=probe.querytask(probe.TASKS["admin_broker"],run=lambda *a,**k:SimpleNamespace(returncode=5,stdout="access denied"))
    assert p["state"]=="missing_or_inaccessible" and p["exists"] is None

def test_classification_requires_every_boot_component():
    data={k:task() for k in ("runtime_watchdog", "runtime_supervisor", "admin_broker")}
    service={"state":"observed","candidate_count":1,"auto_count":1,"all_flags_readable":True}
    got=probe.classify(data,service)
    assert got["headless_entrypoints_observed"]
    assert not got["reboot_allowed"] and not got["post_reboot_recovery_proven"]
    for required in ("runtime_watchdog","runtime_supervisor","admin_broker"):
        changed={**data, required:task(enabled="false")}
        assert not probe.classify(changed,service)["headless_entrypoints_observed"]

def test_missing_service_or_many_service_candidates_blocks():
    data={k:task() for k in probe.TASKS}
    for service in ({"state":"inaccessible"},{"state":"observed","candidate_count":2,"auto_count":2,"all_flags_readable":True}):
        assert not probe.classify(data,service)["headless_entrypoints_observed"]

def test_source_has_no_write_or_arbitrary_shell():
    source=SCRIPT.read_text(encoding="utf-8")
    assert "winreg.SetValue" not in source and "shutdown.exe" not in source
    assert '"/Query"' in source and "shell=False" in source
    assert "OpenProcess" not in source and "STARTUP_AUTOMATION_PASSWORD" not in source


def test_workflow_uses_one_explicit_sync_ref_argument():
    workflow = (Path(__file__).resolve().parents[1]/".github"/"workflows"/
                "desktop-headless-boot-preflight.yml").read_text(encoding="utf-8")
    assert '$syncRef = "origin/$env:GITHUB_REF_NAME"' in workflow
    assert "'--sync-ref', $syncRef," in workflow
    assert "'origin/' + $env:GITHUB_REF_NAME" not in workflow


def test_legacy_watchdog_source_order_and_runner_layout(tmp_path):
    sha="1"*40
    root=tmp_path/"DesktopControlPlaneWatchdog"
    release=root/"releases"/sha/"scripts"
    release.mkdir(parents=True)
    runner=root/"fake_runner";(runner/"bin").mkdir(parents=True)
    for part in (".runner","run.cmd","bin/Runner.Listener.exe"):
        p=runner/part;p.write_text("test",encoding="utf-8")
    python=root/"python.exe";python.write_text("test",encoding="utf-8")
    (root/"metadata.json").write_text(__import__("json").dumps({
        "source_sha":sha,"host":probe.EXPECTED_HOST,
        "release_root":str(release.parent),"runner_home":str(runner),
        "python_executable":str(python)}),encoding="utf-8")
    src=release/"desktop_control_plane_watchdog.py"
    src.write_text("def cycle(meta):\n  a = recover_rdc(meta)\n  b = start_runner(meta)\n\ndef other():\n  pass\n",encoding="utf-8")
    a=probe.legacy_watchdog_readback(root)
    assert a["installed_recovery_order"]=="rdc_first" and not a["runner_recovery_independent"]
    src.write_text("def cycle(meta):\n  b = start_runner(meta)\n  a = recover_rdc(meta)\n\ndef other():\n  pass\n",encoding="utf-8")
    b=probe.legacy_watchdog_readback(root)
    assert b["installed_recovery_order"]=="runner_first" and b["runner_recovery_independent"]

def test_legacy_watchdog_invalid_metadata_fails_closed(tmp_path):
    root=tmp_path/"DesktopControlPlaneWatchdog";root.mkdir()
    (root/"metadata.json").write_text('{"source_sha":"bogus"}',encoding="utf-8")
    result=probe.legacy_watchdog_readback(root)
    assert not result["runner_recovery_independent"]
    assert result["state"]=="invalid_or_inaccessible"
